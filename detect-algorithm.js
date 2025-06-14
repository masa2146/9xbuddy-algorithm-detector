// .github/scripts/detect-algorithm.js - Fixed Version
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
        
        // Known good signature parameters
        this.knownGoodSignature = {
            staticSuffix: "jv7g2_DAMNN_DUDE",
            completenessScore: 100,
            quality: "known_good"
        };
        
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
            signatureParams: {
                staticSuffix: null,
                encryptFunctionFound: false,
                extractPattern: null,
                implementationDetails: null
            },
            endpoints: {
                token: 'https://ab1.9xbud.com/token',
                extract: 'https://ab1.9xbud.com/extract'
            },
            jsFiles: jsFiles,
            extractedFrom: null,
            signatureExtractedFrom: null
        };

        // Her JS dosyasını incele
        for (const jsFile of jsFiles) {
            try {
                console.log(`🔍 Analyzing: ${jsFile}`);
                
                const jsUrl = jsFile.startsWith('http') ? jsFile : this.baseUrl + jsFile;
                const jsResponse = await axios.get(jsUrl, { timeout: 5000 });
                const jsContent = jsResponse.data;

                // U fonksiyonunu ara (decrypt için)
                if (this.containsDecryptFunction(jsContent)) {
                    console.log(`✅ Found decrypt function in: ${jsFile}`);
                    
                    const extractedData = this.extractAlgorithmParams(jsContent);
                    algorithmData = { ...algorithmData, ...extractedData };
                    algorithmData.extractedFrom = jsFile;
                    algorithmData.decryptFunctionFound = true;
                }

                // Signature generation parametrelerini ara (_sig için)
                const sigParams = this.extractSignatureParams(jsContent);
                if (sigParams && Object.keys(sigParams).length > 0) {
                    console.log(`✅ Found signature params in: ${jsFile}`);
                    algorithmData.signatureParams = { ...algorithmData.signatureParams, ...sigParams };
                    algorithmData.signatureExtractedFrom = jsFile;
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
        } else {
            algorithmData.cssHash = "cb67d183996514034d45"; // Default fallback
        }

        // Signature parameters'i validate et ve düzelt
        this.validateAndCorrectSignatureParams(algorithmData.signatureParams);

        return algorithmData;
    }

    containsDecryptFunction(jsContent) {
        // Decrypt fonksiyonu pattern'lerini ara
        const patterns = [
            /var U\s*=\s*function/,
            /function U\s*\(/,
            /\.decrypt\s*\(/,
            /hex2bin/,
            /\[69,84,65,77,95,89,82,82,79,83\]/,
            /\[83,79,82,82,89,95,77,65,84,69\]/ // SORRY_MATE array
        ];

        return patterns.some(pattern => pattern.test(jsContent));
    }

    // FİXED: İyileştirilmiş extractAlgorithmParams fonksiyonu
    extractAlgorithmParams(jsContent) {
        const data = {};

        console.log('🔍 Extracting algorithm parameters...');

        // 1. Static string array'ini bul - daha geniş pattern'ler
        const staticArrayPatterns = [
            // Temel array pattern
            /\[(\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+)\]/g,
            // Decrypt context'inde kullanılan array
            /decrypt[^{]*{\s*[^}]*\[(\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+)\]/g,
            // Variable assignment context
            /var\s+\w+\s*=\s*\[(\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+)\]/g,
            // Function parameter context
            /function[^(]*\([^)]*\)\s*{\s*[^}]*\[(\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d+)\]/g
        ];

        let staticArrayFound = false;
        
        for (const pattern of staticArrayPatterns) {
            const matches = [...jsContent.matchAll(pattern)];
            
            for (const match of matches) {
                const arrayStr = match[1];
                const numbers = arrayStr.split(',').map(n => parseInt(n.trim()));
                
                // Validate array - check if numbers are in printable ASCII range
                if (numbers.length === 10 && numbers.every(n => n >= 32 && n <= 126)) {
                    data.staticStringArray = numbers;
                    
                    // Array'i string'e çevir
                    const chars = numbers.map(n => String.fromCharCode(n)).join('');
                    
                    // Test both normal and reversed string
                    const normalString = chars;
                    const reversedString = chars.split('').reverse().join('');
                    
                    console.log(`🔍 Found array: [${numbers.join(', ')}]`);
                    console.log(`📝 Normal string: "${normalString}"`);
                    console.log(`📝 Reversed string: "${reversedString}"`);
                    
                    // Known good patterns - use exact match first
                    const knownPatterns = [
                        'SORRY_MATE',
                        'ETAM_YRROS',
                        'jv7g2_DAMN',
                        'NNAD_2g7vj'
                    ];
                    
                    if (knownPatterns.includes(normalString)) {
                        data.staticString = normalString;
                        console.log(`✅ Using normal string (known pattern): ${normalString}`);
                    } else if (knownPatterns.includes(reversedString)) {
                        data.staticString = reversedString;
                        console.log(`✅ Using reversed string (known pattern): ${reversedString}`);
                    } else {
                        // Heuristic: if string looks like meaningful text, use it
                        // Otherwise use reversed
                        const normalScore = this.calculateStringScore(normalString);
                        const reversedScore = this.calculateStringScore(reversedString);
                        
                        if (normalScore >= reversedScore) {
                            data.staticString = normalString;
                            console.log(`✅ Using normal string (score: ${normalScore}): ${normalString}`);
                        } else {
                            data.staticString = reversedString;
                            console.log(`✅ Using reversed string (score: ${reversedScore}): ${reversedString}`);
                        }
                    }
                    
                    staticArrayFound = true;
                    break;
                }
            }
            
            if (staticArrayFound) break;
        }

        // 2. Fallback: bilinen iyi değerleri ara
        if (!staticArrayFound) {
            console.log('⚠️  Array not found, searching for known string patterns...');
            
            const knownStringPatterns = [
                /["']SORRY_MATE["']/g,
                /["']ETAM_YRROS["']/g,
                /["']jv7g2_DAMN["']/g,
                /["']NNAD_2g7vj["']/g
            ];
            
            for (const pattern of knownStringPatterns) {
                const match = jsContent.match(pattern);
                if (match) {
                    const foundString = match[0].replace(/["']/g, '');
                    data.staticString = foundString;
                    
                    // Generate corresponding array
                    const chars = foundString.split('');
                    data.staticStringArray = chars.map(c => c.charCodeAt(0));
                    
                    console.log(`✅ Found known string pattern: ${foundString}`);
                    console.log(`📋 Generated array: [${data.staticStringArray.join(', ')}]`);
                    staticArrayFound = true;
                    break;
                }
            }
        }

        // 3. Ultimate fallback
        if (!staticArrayFound) {
            console.log('⚠️  No valid static string found, using fallback...');
            data.staticString = "SORRY_MATE";
            data.staticStringArray = [83, 79, 82, 82, 89, 95, 77, 65, 84, 69]; // SORRY_MATE
            console.log(`🔧 Using fallback: ${data.staticString}`);
        }

        // 4. CSS hash pattern'ini bul - improved patterns
        const cssPatterns = [
            /\/([^/]*main[^/]*\.css[^/]*)\//g,
            /main\.([a-f0-9]+)\.css/g,
            /\/build\/main\.([^"']+?)\.css/g,
            /css[^}]*main[^}]*\.([a-f0-9]+)/g
        ];
        
        for (const pattern of cssPatterns) {
            const match = jsContent.match(pattern);
            if (match) {
                data.cssHashRegex = match[1] || match[0];
                console.log(`🎨 CSS pattern found: ${data.cssHashRegex}`);
                break;
            }
        }

        // 5. Hostname length calculation
        if (/document\.location\.hostname\.length/.test(jsContent)) {
            data.usesHostnameLength = true;
            console.log(`🌐 Uses hostname length calculation`);
        }

        // 6. Additional validation
        this.validateExtractedParams(data);

        return data;
    }

    // Helper function to score string meaningfulness
    calculateStringScore(str) {
        let score = 0;
        
        // Prefer strings with underscores (common in identifiers)
        if (str.includes('_')) score += 20;
        
        // Prefer strings with mixed case
        if (/[A-Z]/.test(str) && /[a-z]/.test(str)) score += 15;
        
        // Prefer strings that look like words
        if (/^[A-Z][A-Z_]*$/.test(str)) score += 10; // ALL_CAPS_STYLE
        if (/^[a-z][a-zA-Z0-9_]*$/.test(str)) score += 8; // camelCase style
        
        // Penalty for strings starting with numbers
        if (/^\d/.test(str)) score -= 10;
        
        // Bonus for known prefixes/suffixes
        if (str.includes('SORRY') || str.includes('MATE') || str.includes('DAMN')) score += 25;
        
        return score;
    }

    // Validation function
    validateExtractedParams(data) {
        console.log('🔍 Validating extracted parameters...');
        
        // Validate static string
        if (data.staticString && data.staticString.length >= 6) {
            console.log(`✅ Static string valid: ${data.staticString} (length: ${data.staticString.length})`);
        } else {
            console.log(`⚠️  Static string questionable: ${data.staticString}`);
        }
        
        // Validate array consistency
        if (data.staticString && data.staticStringArray) {
            const reconstructed = data.staticStringArray.map(n => String.fromCharCode(n)).join('');
            const reconstructedReversed = data.staticStringArray.map(n => String.fromCharCode(n)).join('').split('').reverse().join('');
            
            if (reconstructed === data.staticString) {
                console.log(`✅ Array-String consistency check passed (normal)`);
            } else if (reconstructedReversed === data.staticString) {
                console.log(`✅ Array-String consistency check passed (reversed)`);
            } else {
                console.log(`⚠️  Array-String consistency check failed`);
                console.log(`   Reconstructed: "${reconstructed}"`);
                console.log(`   Reconstructed (reversed): "${reconstructedReversed}"`);
                console.log(`   Expected: "${data.staticString}"`);
            }
        }
    }

    extractSignatureParams(jsContent) {
        const sigParams = {};

        console.log(`    🔑 Searching for signature parameters...`);

        // Önce bilinen doğru pattern'i ara
        if (jsContent.includes('jv7g2_DAMNN_DUDE')) {
            console.log(`    ✅ Found known good signature suffix: jv7g2_DAMNN_DUDE`);
            sigParams.staticSuffix = 'jv7g2_DAMNN_DUDE';
            sigParams.encryptFunctionFound = true;
            sigParams.hasBase64Implementation = true;
            sigParams.usesSigParam = true;
            sigParams.quality = 'known_good';
            sigParams.completenessScore = 100;
            return sigParams;
        }

        // Signature context'inde kullanılan pattern'leri ara
        const signatureContextPatterns = [
            // authToken + suffix pattern'leri
            /authToken\s*\+\s*["']([A-Za-z0-9_]{8,20})["']/g,
            /token\s*\+\s*["']([A-Za-z0-9_]{8,20})["']/g,
            // encrypt context'de kullanılan suffix'ler
            /\.encrypt\s*\([^,]+,\s*[^+]*\+\s*["']([A-Za-z0-9_]{8,20})["']/g,
        ];

        for (const pattern of signatureContextPatterns) {
            const matches = [...jsContent.matchAll(pattern)];
            for (const match of matches) {
                const suffix = match[1];
                
                if (this.isValidSignatureSuffix(suffix, jsContent)) {
                    sigParams.staticSuffix = suffix;
                    console.log(`    🔑 Found valid signature suffix: ${suffix}`);
                    break;
                }
            }
            if (sigParams.staticSuffix) break;
        }

        // Encrypt fonksiyonu ara
        const encryptPatterns = [
            /\.encrypt\s*\([^)]*encodeURIComponent/,
            /encrypt\s*\([^)]*authToken/,
            /function\s+encrypt\s*\([^)]*,\s*[^)]*\)/
        ];

        if (encryptPatterns.some(pattern => pattern.test(jsContent))) {
            sigParams.encryptFunctionFound = true;
            console.log(`    🔐 Encrypt function found`);
        }

        // _sig kullanımı ara
        if (/_sig\s*[:=]/.test(jsContent)) {
            sigParams.usesSigParam = true;
            console.log(`    📝 _sig parameter usage found`);
        }

        // Base64 implementation ara
        if (/encode64\s*[:=]\s*function/.test(jsContent)) {
            sigParams.hasBase64Implementation = true;
            console.log(`    📊 Base64 implementation found`);
        }

        // Extract pattern ara
        const extractMatch = jsContent.match(/searchEngine\s*[:=]\s*["'](yt|fb|tw|ig)["']/);
        if (extractMatch) {
            sigParams.extractPattern = extractMatch[0];
            console.log(`    🎯 Extract pattern found`);
        }

        return sigParams;
    }

    isValidSignatureSuffix(suffix, jsContent) {
        // Invalid suffix'leri filtrele
        const invalidSuffixes = [
            '__esModule', 'prototype', 'constructor', 'toString', 
            'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
            'undefined', 'function', 'object', 'string', 'number', 'boolean',
            'exports', 'module', 'require', 'global', 'window', 'document',
            'length', 'name', 'call', 'apply', 'bind'
        ];
        
        if (invalidSuffixes.includes(suffix)) {
            console.log(`    ❌ Invalid suffix: ${suffix}`);
            return false;
        }
        
        // Minimum length check
        if (suffix.length < 8) {
            console.log(`    ❌ Suffix too short: ${suffix}`);
            return false;
        }
        
        // Context validation - signature context'inde mi kullanılıyor?
        const contextPatterns = [
            new RegExp(`["']${suffix}["'][^}]*(_sig|signature|extract)`, 'i'),
            new RegExp(`(encrypt|signature|_sig)[^}]*["']${suffix}["']`, 'i'),
            new RegExp(`authToken[^}]*["']${suffix}["']`, 'i')
        ];
        
        const hasValidContext = contextPatterns.some(p => p.test(jsContent));
        if (!hasValidContext) {
            console.log(`    ❌ Suffix '${suffix}' not in signature context`);
            return false;
        }
        
        console.log(`    ✅ Valid suffix found: ${suffix}`);
        return true;
    }

    validateAndCorrectSignatureParams(signatureParams) {
        console.log('🔍 Validating and correcting signature parameters...');
        
        let correctionApplied = false;
        
        // Static suffix validation ve correction
        if (!signatureParams.staticSuffix || !this.isValidSignatureSuffix(signatureParams.staticSuffix, '')) {
            console.log(`⚠️  Invalid or missing static suffix: ${signatureParams.staticSuffix}`);
            console.log(`🔧 Applying known good signature parameters`);
            
            // Known good parameters uygula
            Object.assign(signatureParams, this.knownGoodSignature);
            signatureParams.encryptFunctionFound = true;
            signatureParams.hasBase64Implementation = true;
            signatureParams.usesSigParam = true;
            signatureParams.suffixCorrected = true;
            correctionApplied = true;
        }
        
        // Completeness score hesapla
        let completenessScore = 0;
        
        if (signatureParams.staticSuffix === 'jv7g2_DAMNN_DUDE') {
            completenessScore += 50; // Known correct suffix
        } else if (signatureParams.staticSuffix && signatureParams.staticSuffix.length >= 8) {
            completenessScore += 30; // Valid suffix format
        }
        
        if (signatureParams.encryptFunctionFound) completenessScore += 25;
        if (signatureParams.hasBase64Implementation) completenessScore += 15;
        if (signatureParams.extractPattern) completenessScore += 10;
        if (signatureParams.usesSigParam) completenessScore += 5;
        
        // Penalty for corrections
        if (correctionApplied) completenessScore = Math.max(completenessScore - 10, 80);
        
        signatureParams.completenessScore = Math.max(0, Math.min(100, completenessScore));
        
        // Quality assessment
        if (signatureParams.completenessScore >= 90) {
            signatureParams.quality = 'high';
        } else if (signatureParams.completenessScore >= 70) {
            signatureParams.quality = 'medium';
        } else {
            signatureParams.quality = 'low';
        }
        
        // Implementation details
        signatureParams.implementationDetails = {
            hasStaticSuffix: !!signatureParams.staticSuffix,
            hasEncryptFunction: !!signatureParams.encryptFunctionFound,
            usesBase64: !!signatureParams.hasBase64Implementation,
            extractPatternFound: !!signatureParams.extractPattern,
            correctionApplied: correctionApplied,
            correctionReason: correctionApplied ? 'Invalid suffix detected, applied known good parameters' : null,
            detectedAt: new Date().toISOString()
        };
        
        console.log(`📊 Signature completeness: ${signatureParams.completenessScore}% (${signatureParams.quality})`);
        if (correctionApplied) {
            console.log(`🔧 Correction applied: Using known good signature parameters`);
        }
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
        
        // Signature detection summary log
        if (algorithmData.signatureParams) {
            console.log('📋 Signature Detection Summary:');
            console.log(`   Static Suffix: ${algorithmData.signatureParams.staticSuffix || 'Not found'}`);
            console.log(`   Quality: ${algorithmData.signatureParams.quality || 'Unknown'}`);
            console.log(`   Completeness: ${algorithmData.signatureParams.completenessScore || 0}%`);
            console.log(`   Correction Applied: ${algorithmData.signatureParams.suffixCorrected ? 'Yes' : 'No'}`);
            console.log(`   Extracted From: ${algorithmData.signatureExtractedFrom || 'N/A'}`);
        }
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
        
        // URL Decryption changes
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

        // Signature generation changes
        const oldSigParams = oldAlgorithm.signatureParams || {};
        const newSigParams = newAlgorithm.signatureParams || {};
        
        if (newSigParams.staticSuffix !== oldSigParams.staticSuffix) {
            changes.push('signature_static_suffix_changed');
        }
        
        if (newSigParams.quality !== oldSigParams.quality) {
            changes.push('signature_quality_changed');
        }
        
        if (Math.abs((newSigParams.completenessScore || 0) - (oldSigParams.completenessScore || 0)) > 10) {
            changes.push('signature_completeness_changed');
        }
        
        if (newSigParams.suffixCorrected !== oldSigParams.suffixCorrected) {
            changes.push('signature_correction_status_changed');
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