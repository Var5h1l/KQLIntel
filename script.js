// --- DOM Element References ---
const dom = {
    // Input
    toggleUrlBtn: document.getElementById('toggle-url'),
    toggleTextBtn: document.getElementById('toggle-text'),
    urlContainer: document.getElementById('input-url-container'),
    textContainer: document.getElementById('input-text-container'),
    urlInput: document.getElementById('url-input'),
    textInput: document.getElementById('text-input'),
    analyzeBtn: document.getElementById('analyze-btn'),
    spinner: document.getElementById('spinner'),
    
    // AI Selection
    providerSelect: document.getElementById('provider-select'),
    modelSelect: document.getElementById('model-select'),
    modelSelectLabel: document.getElementById('model-select-label'),
    azureSettingsPrompt: document.getElementById('azure-settings-prompt'),
    azureConfigureBtn: document.getElementById('azure-configure-btn'),

    // Results
    resultsSection: document.getElementById('results-section'),
    guaranteedQueriesContainer: document.getElementById('guaranteed-queries-container'),
    guaranteedQueriesList: document.getElementById('guaranteed-queries-list'),
    
    // Threat Summary
    threatSummaryContainer: document.getElementById('threat-summary-container'),
    generateSummaryBtn: document.getElementById('generate-summary-btn'),
    summarySpinner: document.getElementById('summary-spinner'),
    threatSummaryContent: document.getElementById('threat-summary-content'),
    summaryControls: document.getElementById('summary-controls'),

    // AI Assisted
    aiAssistedContainer: document.getElementById('ai-assisted-container'),
    suggestQueriesBtn: document.getElementById('suggest-queries-btn'),
    aiSpinner: document.getElementById('ai-spinner'),
    aiAssistedQueriesList: document.getElementById('ai-assisted-queries-list'),

    // Mitigation Suggestions
    mitigationContainer: document.getElementById('mitigation-container'),
    suggestMitigationsBtn: document.getElementById('suggest-mitigations-btn'),
    mitigationSpinner: document.getElementById('mitigation-spinner'),
    mitigationContent: document.getElementById('mitigation-content'),
    mitigationControls: document.getElementById('mitigation-controls'),

    // Settings Modal & Theme
    settingsBtn: document.getElementById('settings-btn'),
    settingsModal: document.getElementById('settings-modal'),
    settingsSaveBtn: document.getElementById('settings-save-btn'),
    settingsCancelBtn: document.getElementById('settings-cancel-btn'),
    themeToggleBtn: document.getElementById('theme-toggle-btn'),
    themeSunIcon: document.getElementById('theme-sun-icon'),
    themeMoonIcon: document.getElementById('theme-moon-icon'),
    googleKeyInput: document.getElementById('google-key-input'),
    openaiKeyInput: document.getElementById('openai-key-input'),
    anthropicKeyInput: document.getElementById('anthropic-key-input'),
    openrouterKeyInput: document.getElementById('openrouter-key-input'),
    azureKeyInput: document.getElementById('azure-key-input'),
    azureEndpointInput: document.getElementById('azure-endpoint-input'),
    azureDeploymentInput: document.getElementById('azure-deployment-input'),

    // Info Modal
    infoBtn: document.getElementById('info-btn'),
    infoModal: document.getElementById('info-modal'),
    infoCloseBtn: document.getElementById('info-close-btn'),

    // Global
    messageBox: document.getElementById('message-box'),
};

// --- State Variables ---
let state = {
    extractedIOCs: {},
    lastAnalyzedText: '',
    lastSummary: '',
    apiKeys: {},
};

// --- Configuration ---
const config = {
    kqlTemplates: {
        ipv4: 'DeviceNetworkEvents | where RemoteIP == "{ioc}"',
        domain: 'DeviceNetworkEvents | where RemoteUrl has "{ioc}" or RemoteIP in ((find where DomainName == "{ioc}" | project IPAddress))',
        md5: 'DeviceFileEvents | where MD5 == "{ioc}"',
        sha1: 'DeviceFileEvents | where SHA1 == "{ioc}"',
        sha256: 'DeviceFileEvents | where SHA256 == "{ioc}"',
        filename: 'DeviceFileEvents | where FileName == "{ioc}"',
        url: 'DeviceNetworkEvents | where RemoteUrl == "{ioc}"'
    },
    modelsByProvider: {
        google: ['gemini-1.5-flash-latest', 'gemini-1.5-pro-latest', 'gemini-pro'],
        openai: ['gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'],
        anthropic: ['claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307'],
        openrouter: [
            'nousresearch/nous-hermes-2-mixtral-8x7b-dpo',
            'mistralai/mistral-7b-instruct-v0.2',
            'google/gemma-7b-it',
            'openchat/openchat-7b'
        ],
        azure: ['custom (defined by deployment name)']
    }
};

// --- Initialization ---
function initialize() {
    loadApiKeys();
    applyInitialTheme();
    setupEventListeners();
    updateModelSelector();
    dom.toggleUrlBtn.classList.add('active');
}

// --- Event Listeners Setup ---
function setupEventListeners() {
    dom.toggleUrlBtn.addEventListener('click', () => switchInputType('url'));
    dom.toggleTextBtn.addEventListener('click', () => switchInputType('text'));
    dom.analyzeBtn.addEventListener('click', handleAnalysis);
    dom.generateSummaryBtn.addEventListener('click', handleThreatSummary);
    dom.suggestQueriesBtn.addEventListener('click', handleAiSuggestions);
    dom.suggestMitigationsBtn.addEventListener('click', handleMitigationSuggestions);
    
    dom.settingsBtn.addEventListener('click', () => dom.settingsModal.classList.remove('hidden'));
    dom.settingsCancelBtn.addEventListener('click', () => dom.settingsModal.classList.add('hidden'));
    dom.settingsSaveBtn.addEventListener('click', saveApiKeys);
    
    dom.themeToggleBtn.addEventListener('click', handleThemeToggle);
    dom.providerSelect.addEventListener('change', updateModelSelector);
    dom.azureConfigureBtn.addEventListener('click', () => dom.settingsModal.classList.remove('hidden'));

    // Info Modal Listeners
    dom.infoBtn.addEventListener('click', () => dom.infoModal.classList.remove('hidden'));
    dom.infoCloseBtn.addEventListener('click', () => dom.infoModal.classList.add('hidden'));
    dom.infoModal.addEventListener('click', (e) => {
        if (e.target === dom.infoModal) {
            dom.infoModal.classList.add('hidden');
        }
    });
}

// --- UI Functions ---
function showMessage(text, type = 'success') {
    dom.messageBox.textContent = text;
    dom.messageBox.className = 'message-box fixed bottom-5 right-20 text-white px-5 py-3 rounded-lg shadow-lg';
    dom.messageBox.classList.add(type);
    dom.messageBox.classList.remove('hidden');
    setTimeout(() => { dom.messageBox.classList.add('hidden'); }, 4000);
}

function switchInputType(type) {
    dom.urlContainer.classList.toggle('hidden', type !== 'url');
    dom.textContainer.classList.toggle('hidden', type === 'url');
    dom.toggleUrlBtn.classList.toggle('active', type === 'url');
    dom.toggleTextBtn.classList.toggle('active', type !== 'url');
}

function updateModelSelector() {
    const provider = dom.providerSelect.value;
    const models = config.modelsByProvider[provider] || [];
    const isAzure = provider === 'azure';

    dom.modelSelect.innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join('');
    dom.modelSelect.classList.toggle('hidden', isAzure);
    dom.modelSelectLabel.classList.toggle('hidden', isAzure);
    dom.azureSettingsPrompt.classList.toggle('hidden', !isAzure);
}

function createKqlQueryElement(title, query) {
    const div = document.createElement('div');
    div.className = 'kql-query relative font-mono whitespace-pre-wrap break-all p-4 rounded-md';
    const sanitizedQuery = query.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    div.innerHTML = `
        <button class="copy-btn absolute top-2 right-2 px-2 py-1 rounded text-xs opacity-0 transition-opacity">Copy</button>
        <p class="comment text-sm mb-2">// ${title}</p>
        <p>${sanitizedQuery}</p>`;
    
    const copyBtn = div.querySelector('.copy-btn');
    copyBtn.addEventListener('click', (e) => copyToClipboard(query, e.target));

    div.addEventListener('mouseover', () => copyBtn.style.opacity = '1');
    div.addEventListener('mouseout', () => copyBtn.style.opacity = '0');

    return div;
}

function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        buttonElement.textContent = 'Copied!';
        showMessage('Copied to clipboard!', 'success');
        setTimeout(() => { buttonElement.textContent = 'Copy'; }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
        showMessage('Failed to copy.', 'error');
    });
}

function setLoadingState(isLoading, type) {
    const elements = {
        analyze: { spinner: dom.spinner, btn: dom.analyzeBtn },
        summary: { spinner: dom.summarySpinner, btn: dom.generateSummaryBtn },
        ai: { spinner: dom.aiSpinner, btn: dom.suggestQueriesBtn },
        mitigation: { spinner: dom.mitigationSpinner, btn: dom.suggestMitigationsBtn }
    };
    const el = elements[type];
    if (el) {
        el.spinner.classList.toggle('hidden', !isLoading);
        el.btn.disabled = isLoading;
    }
}

function resetResults() {
    dom.resultsSection.classList.add('hidden');
    state.extractedIOCs = {};
    state.lastAnalyzedText = '';
    state.lastSummary = '';
    
    [dom.guaranteedQueriesContainer, dom.threatSummaryContainer, dom.aiAssistedContainer, dom.mitigationContainer].forEach(c => c.classList.add('hidden'));
    dom.guaranteedQueriesList.innerHTML = '';
    dom.threatSummaryContent.innerHTML = '';
    dom.aiAssistedQueriesList.innerHTML = '';
    dom.mitigationContent.innerHTML = '';

    dom.summaryControls.classList.remove('hidden');
    dom.mitigationControls.classList.remove('hidden');
}

// --- Theme Management ---
function applyInitialTheme() {
    const savedTheme = localStorage.getItem('kqlintel-theme') || 'dark';
    setTheme(savedTheme);
}

function handleThemeToggle() {
    const currentTheme = document.body.dataset.theme;
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

function setTheme(theme) {
    document.body.dataset.theme = theme;
    localStorage.setItem('kqlintel-theme', theme);
    if (theme === 'light') {
        dom.themeSunIcon.classList.add('hidden');
        dom.themeMoonIcon.classList.remove('hidden');
    } else {
        dom.themeSunIcon.classList.remove('hidden');
        dom.themeMoonIcon.classList.add('hidden');
    }
}

// --- API Key Management ---
function saveApiKeys() {
    state.apiKeys = {
        google: dom.googleKeyInput.value,
        openai: dom.openaiKeyInput.value,
        anthropic: dom.anthropicKeyInput.value,
        openrouter: dom.openrouterKeyInput.value,
        azure: {
            key: dom.azureKeyInput.value,
            endpoint: dom.azureEndpointInput.value,
            deployment: dom.azureDeploymentInput.value,
        }
    };
    localStorage.setItem('kqlintel-apikeys', JSON.stringify(state.apiKeys));
    showMessage('API Keys saved!', 'success');
    dom.settingsModal.classList.add('hidden');
}

function loadApiKeys() {
    const savedKeys = localStorage.getItem('kqlintel-apikeys');
    if (savedKeys) {
        state.apiKeys = JSON.parse(savedKeys);
        dom.googleKeyInput.value = state.apiKeys.google || '';
        dom.openaiKeyInput.value = state.apiKeys.openai || '';
        dom.anthropicKeyInput.value = state.apiKeys.anthropic || '';
        dom.openrouterKeyInput.value = state.apiKeys.openrouter || '';
        if (state.apiKeys.azure) {
            dom.azureKeyInput.value = state.apiKeys.azure.key || '';
            dom.azureEndpointInput.value = state.apiKeys.azure.endpoint || '';
            dom.azureDeploymentInput.value = state.apiKeys.azure.deployment || '';
        }
    }
}

function checkApiKey(provider) {
     if (provider === 'azure') {
        if (!state.apiKeys.azure || !state.apiKeys.azure.key || !state.apiKeys.azure.endpoint || !state.apiKeys.azure.deployment) {
            showMessage(`Azure credentials are incomplete. Please add Key, Endpoint, and Deployment Name in Settings.`, 'error');
            dom.settingsModal.classList.remove('hidden');
            return false;
        }
    } else if (!state.apiKeys[provider]) {
        showMessage(`API Key for ${provider} is missing. Please add it in Settings.`, 'error');
        dom.settingsModal.classList.remove('hidden');
        return false;
    }
    return true;
}

// --- Core Logic ---
async function handleAnalysis() {
    if (!checkApiKey(dom.providerSelect.value)) return;
    
    setLoadingState(true, 'analyze');
    resetResults();

    try {
        const isUrlMode = dom.toggleUrlBtn.classList.contains('active');
        let textToAnalyze;
        let sourceDomain = null;

        if (isUrlMode) {
            const urlValue = dom.urlInput.value.trim();
            if (!urlValue) {
                showMessage('Please provide a URL to analyze.', 'error');
                setLoadingState(false, 'analyze');
                return;
            }
            try {
                const url = new URL(urlValue);
                sourceDomain = url.hostname;
            } catch (e) {
                showMessage('Invalid URL provided.', 'error');
                setLoadingState(false, 'analyze');
                return;
            }
            textToAnalyze = await fetchUrlContent(urlValue);
            if (!textToAnalyze) {
                 setLoadingState(false, 'analyze');
                 return;
            }
        } else {
            textToAnalyze = dom.textInput.value.trim();
             if (!textToAnalyze) {
                showMessage('Please provide some text to analyze.', 'error');
                setLoadingState(false, 'analyze');
                return;
            }
        }
        
        state.lastAnalyzedText = textToAnalyze;
        showMessage('Analyzing text with AI...', 'success');
        
        let iocPrompt = `You are an expert cybersecurity threat intelligence analyst with a specialization in parsing unstructured reports. Your primary task is to extract ONLY malicious Indicators of Compromise (IOCs) from the provided text.

**CRITICAL INSTRUCTIONS:**
1.  **Focus on Explicit IOCs:** Give the highest priority to items listed under explicit headings like "Indicators of Compromise", "IOCs", "Malicious Hashes", "C2 Domains", etc. If no such section exists, be extremely cautious.
2.  **Context is Key:** Do NOT extract every domain, URL, or IP address you find. Analyze the surrounding text. An IOC is typically presented as a threat artifact. A URL in a reference link at the bottom of a page is NOT an IOC.
3.  **Ignore Legitimate & Reference Domains:** You MUST ignore common, legitimate domains and URLs unless they are explicitly identified as malicious. This includes:
    * The source domain of the report itself (${sourceDomain || 'the source website'}).
    * Major tech and security company domains (e.g., microsoft.com, google.com, apple.com, virustotal.com, github.com).
    * Social media links (e.g., twitter.com, linkedin.com).
    * URLs in footnotes, references, or "further reading" sections.
4.  **Identify True IOCs:** Look for file hashes (MD5, SHA1, SHA256), suspicious IP addresses, command-and-control (C2) domains, malicious filenames (e.g., malware.exe, payload.dll), and URLs pointing directly to malicious content.
5.  **Be Exhaustive:** You MUST extract ALL indicators of each type from the entire text. Do not stop after finding just one. Scrutinize the entire provided text, especially tables and lists, to ensure every single IOC is included in your final JSON response.

From the text below, extract the IOCs and return them as a valid JSON object with the following keys: "ipv4", "domain", "md5", "sha1", "sha256", "filename", "url". If you find absolutely no items that you can confidently identify as malicious IOCs based on these rules, return a JSON object with empty arrays for each key.

Text to analyze:
---
${textToAnalyze}
---`;

        const iocSchema = { type: "OBJECT", properties: { "ipv4": { "type": "ARRAY", "items": { "type": "STRING" } }, "domain": { "type": "ARRAY", "items": { "type": "STRING" } }, "md5": { "type": "ARRAY", "items": { "type": "STRING" } }, "sha1": { "type": "ARRAY", "items": { "type": "STRING" } }, "sha256": { "type": "ARRAY", "items": { "type": "STRING" } }, "filename": { "type": "ARRAY", "items": { "type": "STRING" } }, "url": { "type": "ARRAY", "items": { "type": "STRING" } } } };
        
        const iocsResult = await callLLM(iocPrompt, iocSchema);
        const iocs = JSON.parse(iocsResult);
        
        const iocsFound = iocs && Object.values(iocs).some(arr => arr.length > 0);
        
        dom.resultsSection.classList.remove('hidden');
        dom.guaranteedQueriesContainer.classList.remove('hidden');
        displayGuaranteedQueries(iocs);

        if (iocsFound) {
            state.extractedIOCs = iocs;
            dom.threatSummaryContainer.classList.remove('hidden');
            dom.aiAssistedContainer.classList.remove('hidden');
            dom.mitigationContainer.classList.remove('hidden');
            showMessage("AI analysis successful! Found IOCs.", "success");
        } else {
            showMessage("AI analysis complete. No standard IOCs found.", "success");
        }
    } catch (error) {
        console.error("Analysis failed:", error);
        showMessage(`Analysis failed: ${error.message}`, 'error');
    } finally {
        setLoadingState(false, 'analyze');
    }
}

async function handleThreatSummary() {
    if (!checkApiKey(dom.providerSelect.value)) return;
    if (!state.lastAnalyzedText) {
        showMessage("Please run an analysis first.", 'error');
        return;
    }
    setLoadingState(true, 'summary');
    try {
        const prompt = `You are a senior cybersecurity analyst. Based on the following threat intelligence text and its extracted IOCs, provide a concise summary (2-3 paragraphs) for a security operations team. Explain the threat's nature, behavior, and impact. Return only the summary text itself, without any titles, JSON formatting, or other conversational text.\n\nIOCs:\n${JSON.stringify(state.extractedIOCs)}\n\nOriginal Text:\n---\n${state.lastAnalyzedText}\n---`;
        
        const summary = await callLLM(prompt, null);
        state.lastSummary = summary; // Save summary for mitigation step
        
        dom.threatSummaryContent.innerHTML = `<p>${summary.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>')}</p>`;
        dom.summaryControls.classList.add('hidden');
        showMessage("Threat summary generated!", "success");
    } catch (error) {
        console.error("Failed to get threat summary:", error);
        showMessage(`Error generating summary: ${error.message}`, 'error');
    } finally {
        setLoadingState(false, 'summary');
    }
}

async function handleAiSuggestions() {
    if (!checkApiKey(dom.providerSelect.value)) return;
    if (Object.keys(state.extractedIOCs).length === 0) {
        showMessage("No IOCs found to generate advanced queries from.", 'error');
        return;
    }
    setLoadingState(true, 'ai');
    dom.aiAssistedQueriesList.innerHTML = '';
    try {
        const prompt = `You are a senior threat hunter specializing in KQL. Given these IOCs, generate 3-5 advanced KQL queries to find related suspicious activity. Use operators like 'join', 'summarize', and look for behavioral patterns. Return ONLY a valid JSON array of objects, each with a "title" and a "query" key.\n\nIOCs:\n${JSON.stringify(state.extractedIOCs)}`;
        const schema = { type: "ARRAY", items: { type: "OBJECT", properties: { "title": { "type": "STRING" }, "query": { "type": "STRING" } }, required: ["title", "query"] } };
        const result = await callLLM(prompt, schema);
        const queries = JSON.parse(result);
        displayAdvancedQueries(queries);
        showMessage("Advanced queries generated!", "success");
    } catch (error) {
        console.error("Failed to get advanced queries:", error);
        showMessage(`Error generating advanced queries: ${error.message}`, 'error');
    } finally {
        setLoadingState(false, 'ai');
    }
}

async function handleMitigationSuggestions() {
    if (!checkApiKey(dom.providerSelect.value)) return;
    if (Object.keys(state.extractedIOCs).length === 0) {
        showMessage("No IOCs found to suggest mitigations from.", 'error');
        return;
    }
    if (!state.lastSummary) {
        showMessage("Please generate a threat summary first.", 'error');
        return;
    }

    setLoadingState(true, 'mitigation');
    try {
        const prompt = `You are a principal security engineer. Based on the following threat summary and IOCs, provide a prioritized list of actionable mitigation steps for a Security Operations Center (SOC) and IT administrators. Group suggestions by theme (e.g., Network, Endpoint, Identity). Be specific and practical. Return only the mitigation steps as a well-formatted text response.\n\nThreat Summary:\n${state.lastSummary}\n\nIOCs:\n${JSON.stringify(state.extractedIOCs)}`;
        
        const mitigations = await callLLM(prompt, null);
        
        dom.mitigationContent.innerHTML = `<p>${mitigations.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>')}</p>`;
        dom.mitigationControls.classList.add('hidden');
        showMessage("Mitigation steps generated!", "success");
    } catch (error) {
        console.error("Failed to get mitigation suggestions:", error);
        showMessage(`Error generating mitigations: ${error.message}`, 'error');
    } finally {
        setLoadingState(false, 'mitigation');
    }
}

function displayGuaranteedQueries(iocs) {
    dom.guaranteedQueriesList.innerHTML = '';
    let count = 0;
    for (const type in iocs) {
        if (config.kqlTemplates[type] && iocs[type]?.length > 0) {
            iocs[type].forEach(ioc => {
                const query = config.kqlTemplates[type].replace(/{ioc}/g, ioc);
                dom.guaranteedQueriesList.appendChild(createKqlQueryElement(`Hunt for ${type.toUpperCase()} - ${ioc}`, query));
                count++;
            });
        }
    }
    if (count === 0) {
        dom.guaranteedQueriesList.innerHTML = '<p class="text-gray-400">No standard IOCs were found.</p>';
    }
}

function displayAdvancedQueries(queries) {
    dom.aiAssistedQueriesList.innerHTML = '';
    if (queries?.length > 0) {
        queries.forEach(q => dom.aiAssistedQueriesList.appendChild(createKqlQueryElement(q.title, q.query)));
    } else {
        dom.aiAssistedQueriesList.innerHTML = '<p class="text-gray-400">The AI could not suggest any advanced queries.</p>';
    }
}

async function fetchUrlContent(url) {
    const readerApiUrl = `https://r.jina.ai/${encodeURIComponent(url)}`;
    showMessage('Fetching and parsing content with reader API...', 'success');
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 25000);

        const response = await fetch(readerApiUrl, {
            signal: controller.signal,
            headers: { 'Accept': 'text/plain' }
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`Reader API failed with status ${response.status}: ${await response.text()}`);
        }
        
        const textContent = await response.text();

        if (!textContent || textContent.trim() === '') {
            throw new Error("Reader API returned empty content.");
        }
        
        return textContent;

    } catch (error) {
        let errorMsg = error.message;
        if (error.name === 'AbortError' || error.name === 'TimeoutError') {
            errorMsg = "Request to the reader API timed out after 25 seconds.";
        }
        console.error("URL content fetching failed:", error);
        showMessage(`Failed to fetch content: ${errorMsg}`, 'error');
        return null;
    }
}

// --- LLM API Abstraction Layer ---
async function callLLM(prompt, schema) {
    const provider = dom.providerSelect.value;
    const model = dom.modelSelect.value;
    const apiKey = state.apiKeys[provider];

    const apiHandlers = {
        google: callGoogleAPI,
        openai: callOpenAIAPI,
        anthropic: callAnthropicAPI,
        openrouter: callOpenRouterAPI,
        azure: callAzureOpenAIAPI,
    };

    if (!apiHandlers[provider]) {
        throw new Error(`Unsupported provider: ${provider}`);
    }

    return apiHandlers[provider](apiKey, model, prompt, schema);
}

// --- Remote APIs (Key Required) ---
async function callGoogleAPI(apiKey, model, prompt, schema) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    
    let finalPrompt = prompt;
    if (schema) {
        finalPrompt = `${prompt}\n\nImportant: Respond with ONLY a valid JSON object that conforms to the following schema. Do not include any other text, comments, or markdown formatting.\n\nSchema: ${JSON.stringify(schema)}`;
    }

    const payload = { 
        contents: [{ role: "user", parts: [{ text: finalPrompt }] }], 
        generationConfig: { temperature: 0.1 } 
    };

    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(`Google API Error: ${response.statusText} - ${errorBody.error?.message || 'Unknown error'}`);
    }
    const result = await response.json();
    const textResponse = result.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!textResponse) {
        const reason = result.promptFeedback?.blockReason || 'Unknown reason';
        if(reason !== 'Unknown reason') throw new Error(`Request blocked by Google API. Reason: ${reason}`);
        throw new Error("Invalid or empty response from Google API.");
    }
    
    if (!schema) {
        return textResponse;
    }
    
    const jsonMatch = textResponse.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    if (!jsonMatch) throw new Error("Google API did not return valid JSON.");
    return jsonMatch[0];
}

async function callOpenAIAPI(apiKey, model, prompt, schema) {
    const url = 'https://api.openai.com/v1/chat/completions';
    const payload = { 
        model: model, 
        messages: [{ role: "user", content: prompt }], 
        temperature: 0.1 
    };

    if (schema) {
        payload.response_format = { "type": "json_object" };
    }

    const response = await fetch(url, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, 
        body: JSON.stringify(payload) 
    });

     if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(`OpenAI API Error: ${errorBody.error?.message || response.statusText}`);
    }
    const result = await response.json();
    const textResponse = result.choices?.[0]?.message?.content;

    if (!textResponse) throw new Error("Invalid or empty response from OpenAI API.");
    
    if (!schema) {
        return textResponse;
    }
    
    return textResponse;
}

async function callAnthropicAPI(apiKey, model, prompt, schema) {
    const url = 'https://api.anthropic.com/v1/messages';
    let systemPrompt = "You are a helpful assistant.";
    
    if (schema) {
        systemPrompt = `You are a helpful assistant designed to output JSON. Respond with a valid JSON object that conforms to this schema. Do not add any other text. Schema: ${JSON.stringify(schema)}`;
    }

    const payload = { 
        model: model, 
        max_tokens: 4096, 
        system: systemPrompt, 
        messages: [{ role: "user", content: prompt }], 
        temperature: 0.2 
    };
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }, body: JSON.stringify(payload) });
     if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(`Anthropic API Error: ${errorBody.error?.message || response.statusText}`);
    }
    const result = await response.json();
    const textResponse = result.content?.[0]?.text;

    if (!textResponse) throw new Error("Invalid or empty response from Anthropic API.");
    
    if (!schema) {
        return textResponse;
    }

    const jsonMatch = textResponse.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    if (!jsonMatch) throw new Error("Anthropic API did not return valid JSON.");
    return jsonMatch[0];
}

async function callOpenRouterAPI(apiKey, model, prompt, schema) {
    const url = 'https://openrouter.ai/api/v1/chat/completions';
     const payload = { 
        model: model, 
        messages: [{ role: "user", content: prompt }], 
        temperature: 0.1 
    };

    if (schema) {
        payload.response_format = { "type": "json_object" };
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}`, 'HTTP-Referer': `${location.protocol}//${location.host}`, 'X-Title': 'KQLIntel' },
        body: JSON.stringify(payload)
    });
    if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(`OpenRouter API Error: ${errorBody.error?.message || response.statusText}`);
    }
    const result = await response.json();
    const textResponse = result.choices?.[0]?.message?.content;
    
    if (!textResponse) throw new Error("Invalid or empty response from OpenRouter API.");
    
    if (!schema) {
        return textResponse;
    }
    
    return textResponse;
}

async function callAzureOpenAIAPI(apiCredentials, model, prompt, schema) {
    const { key, endpoint, deployment } = apiCredentials;
    const sanitizedEndpoint = endpoint.replace(/\/+$/, "");
    const url = `${sanitizedEndpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-01`;
    
    const payload = { 
        messages: [{ role: "user", content: prompt }], 
        temperature: 0.1 
    };

    if (schema) {
        payload.response_format = { "type": "json_object" };
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api-key': key },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(`Azure API Error: ${errorBody.error?.message || response.statusText}`);
    }
    const result = await response.json();
    const textResponse = result.choices?.[0]?.message?.content;
    
    if (!textResponse) throw new Error("Invalid response from Azure API.");

    if (!schema) {
        return textResponse;
    }
    
    return textResponse;
}


// --- Run Initialization ---
initialize();
