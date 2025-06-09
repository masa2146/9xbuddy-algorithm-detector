// .github/scripts/detect-algorithm.js
const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class AlgorithmDetector {
    constructor() {
        this.baseUrl = 'https://9xbuddy.site';
        this.configPath = path.join(process.cwd(), 'config');
        this.currentConfigPath = path.join(this.configPath, 'algorithm.json');
        this.historyPath = path.join(this.configPath, 'history.json');
        
        // Config directory oluştur
        if (!fs.existsSync(this.configPath)) {
            fs.mkdirSync(this.configPath, { recursive: true });
        }
    }

    async detectChanges() {
        console.log('🔍 Starting algorithm detection...');
        
        try {
            // Mevcut algoritma bilgilerini al
            const currentAlgorithm = await this.extractCurrentAlgorithm();
            console.log('✅ Algorithm extracted successfully');
            
            // Mevcut config'i oku (varsa)
            const existingConfig = this.loadExistingConfig();
            
            // Hash karşılaştırması
            const currentHash = this.generateHash(currentAlgorithm);
            const existingHash = existingConfig ? this.generateHash(existingConfig.algorithm) : null;
            
            console.log(`Current hash: ${currentHash}`);
            console.log(`Existing hash: ${existingHash}`);
            
            if (currentHash !== existingHash) {
                console.log('🚨 Algorithm change detected!');
                await this.saveNewConfig(currentAlgorithm, currentHash);
                await this.updateHistory(currentAlgorithm, currentHash);
                return true;
            } else {
                console.log('✅ No algorithm changes detected');
                // Config'i güncelle (timestamp için)
                await this.updateConfigTimestamp(existingConfig);
                return false;
            }
            
        } catch (error) {
            console.error('❌ Error during detection:', error.message);
            throw error;
        }
    }

    async extractCurrentAlgorithm() {
        console.log('📥 Fetching 9xBuddy homepage...');
        
        // Ana sayfayı al
        const homeResponse = await axios.get(this.baseUrl, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        const $ = cheerio.load(homeResponse.data);
        
        // JavaScript dosyalarını bul
        const jsFiles = [];
        $('script[src]').each((i, elem) => {
            const src = $(elem).attr('src');
            if (src && src.includes('.js') && !src.startsWith('http')) {
                jsFiles.push(src.startsWith('/') ? src : '/' + src);
            }
        });

        console.log(`📜 Found ${jsFiles.length} JS files`);

        let algorithmData = {
            staticString: null,
            staticStringArray: null,
            hostnameLength: 12, // 9xbuddy.site
            cssHashPattern: null,
            decryptFunctionFound: false,
            endpoints: {
                token: 'https://ab1.9xbud.com/token',
                extract: 'https://ab1.9xbud.com/extract'
            },
            jsFiles: jsFiles,
            extractedFrom: null
        };

        // Her JS dosyasını incele
        for (const jsFile of jsFiles) {
            try {
                console.log(`🔍 Analyzing: ${jsFile}`);
                
                const jsUrl = jsFile.startsWith('http') ? jsFile : this.baseUrl + jsFile;
                const jsResponse = await axios.get(jsUrl, { timeout: 5000 });
                const jsContent = jsResponse.data;

                // U fonksiyonunu ara
                if (this.containsDecryptFunction(jsContent)) {
                    console.log(`✅ Found decrypt function in: ${jsFile}`);
                    
                    const extractedData = this.extractAlgorithmParams(jsContent);
                    algorithmData = { ...algorithmData, ...extractedData };
                    algorithmData.extractedFrom = jsFile;
                    algorithmData.decryptFunctionFound = true;
                }

                // CSS hash pattern'ini ara
                const cssPattern = this.extractCssPattern(jsContent);
                if (cssPattern) {
                    algorithmData.cssHashPattern = cssPattern;
                }

            } catch (error) {
                console.log(`⚠️  Error analyzing ${jsFile}: ${error.message}`);
            }
        }

        // CSS hash'i bul
        if (algorithmData.cssHashPattern) {
            algorithmData.cssHash = await this.extractCssHash(homeResponse.data, algorithmData.cssHashPattern);
        }

        return algorithmData;
    }

    containsDecryptFunction(jsContent) {
        // Decrypt fonksiyonu pattern'lerini ara
        const patterns = [
            /var U\s*=\s*function/,
            /function U\s*\(/,
            /\.decrypt\s*\(/,
            /hex2bin/,
            /\[69,84,65,77,95,89,82,82,79,83\]/
        ];

        return patterns.some(pattern => pattern.test(jsContent));
    }

    extractAlgorithmParams(jsContent) {
        const data = {};

        // Static string array'ini bul
        const staticArrayMatch = jsContent.match(/\[(\d+,\d+,\d+,\d+,\d+,\d+,\d+,\d+,\d+,\d+)\]/);
        if (staticArrayMatch) {
            const arrayStr = staticArrayMatch[1];
            const numbers = arrayStr.split(',').map(n => parseInt(n.trim()));
            data.staticStringArray = numbers;
            
            // Array'i string'e çevir
            const chars = numbers.map(n => String.fromCharCode(n)).join('');
            data.staticString = chars.split('').reverse().join('');
            
            console.log(`📋 Static string found: ${data.staticString}`);
        }

        // CSS hash pattern'ini bul
        const cssPatternMatch = jsContent.match(/\/([^/]+main[^/]+\.css[^/]*)\//);
        if (cssPatternMatch) {
            data.cssHashRegex = cssPatternMatch[1];
        }

        // Hostname length calculation'ı bul
        const hostnameMatch = jsContent.match(/document\.location\.hostname\.length/);
        if (hostnameMatch) {
            data.usesHostnameLength = true;
        }

        return data;
    }

    extractCssPattern(jsContent) {
        const patterns = [
            /\/\\?\/build\\?\/main\\?\.\([^)]+\)\.css/g,
            /\/build\/main\.\([^)]+\)\.css/g,
            /main\.\([^)]+\)\.css/g
        ];

        for (const pattern of patterns) {
            const match = jsContent.match(pattern);
            if (match) {
                return match[0];
            }
        }
        return null;
    }

    async extractCssHash(htmlContent, pattern) {
        try {
            // HTML'den CSS dosya linkini bul
            const cssLinkMatch = htmlContent.match(/\/build\/main\.([^"]+?)\.css/);
            if (cssLinkMatch) {
                return cssLinkMatch[1];
            }
        } catch (error) {
            console.log('⚠️  Could not extract CSS hash:', error.message);
        }
        return 'cb67d183996514034d45'; // Default fallback
    }

    generateHash(data) {
        const dataString = JSON.stringify(data, Object.keys(data).sort());
        return crypto.createHash('sha256').update(dataString).digest('hex').substring(0, 16);
    }

    loadExistingConfig() {
        try {
            if (fs.existsSync(this.currentConfigPath)) {
                const configData = fs.readFileSync(this.currentConfigPath, 'utf8');
                return JSON.parse(configData);
            }
        } catch (error) {
            console.log('⚠️  Could not load existing config:', error.message);
        }
        return null;
    }

    async saveNewConfig(algorithmData, hash) {
        const config = {
            version: this.generateVersion(),
            hash: hash,
            lastUpdate: new Date().toISOString(),
            detectedAt: new Date().toISOString(),
            algorithm: algorithmData,
            status: 'active'
        };

        const configJson = JSON.stringify(config, null, 2);
        fs.writeFileSync(this.currentConfigPath, configJson);
        
        console.log('💾 New config saved');
    }

    async updateConfigTimestamp(existingConfig) {
        existingConfig.lastChecked = new Date().toISOString();
        const configJson = JSON.stringify(existingConfig, null, 2);
        fs.writeFileSync(this.currentConfigPath, configJson);
    }

    async updateHistory(algorithmData, hash) {
        let history = [];
        
        try {
            if (fs.existsSync(this.historyPath)) {
                const historyData = fs.readFileSync(this.historyPath, 'utf8');
                history = JSON.parse(historyData);
            }
        } catch (error) {
            console.log('⚠️  Could not load history:', error.message);
        }

        const historyEntry = {
            version: this.generateVersion(),
            hash: hash,
            timestamp: new Date().toISOString(),
            changes: this.detectSpecificChanges(algorithmData, history[0]?.algorithm),
            algorithm: algorithmData
        };

        history.unshift(historyEntry);
        
        // Son 50 değişikliği sakla
        if (history.length > 50) {
            history = history.slice(0, 50);
        }

        const historyJson = JSON.stringify(history, null, 2);
        fs.writeFileSync(this.historyPath, historyJson);
        
        console.log('📚 History updated');
    }

    detectSpecificChanges(newAlgorithm, oldAlgorithm) {
        if (!oldAlgorithm) return ['initial_detection'];
        
        const changes = [];
        
        if (newAlgorithm.staticString !== oldAlgorithm.staticString) {
            changes.push('static_string_changed');
        }
        
        if (newAlgorithm.cssHash !== oldAlgorithm.cssHash) {
            changes.push('css_hash_changed');
        }
        
        if (JSON.stringify(newAlgorithm.endpoints) !== JSON.stringify(oldAlgorithm.endpoints)) {
            changes.push('endpoints_changed');
        }
        
        if (newAlgorithm.extractedFrom !== oldAlgorithm.extractedFrom) {
            changes.push('js_file_changed');
        }
        
        return changes.length > 0 ? changes : ['unknown_change'];
    }

    generateVersion() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hour = String(now.getHours()).padStart(2, '0');
        const minute = String(now.getMinutes()).padStart(2, '0');
        
        return `${year}.${month}.${day}.${hour}${minute}`;
    }
}

// Main execution
async function main() {
    const detector = new AlgorithmDetector();
    
    try {
        const hasChanges = await detector.detectChanges();
        
        if (hasChanges) {
            console.log('🎉 Detection completed - Changes found!');
            process.exit(0);
        } else {
            console.log('✅ Detection completed - No changes');
            process.exit(0);
        }
        
    } catch (error) {
        console.error('💥 Detection failed:', error);
        process.exit(1);
    }
}

// Script çalıştırılıyorsa main fonksiyonu çağır
if (require.main === module) {
    main();
}

module.exports = AlgorithmDetector;
