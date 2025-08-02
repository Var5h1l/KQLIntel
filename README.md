<div align="center">

# KQLIntel 🚀

### _From Unstructured Threat Intel to Actionable KQL Queries in Seconds_

</div>

<p align="center">
  <img alt="GitHub language count" src="https://img.shields.io/github/languages/count/Var5h1l/KQLIntel?color=%236366f1">
  <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/Var5h1l/KQLIntel?color=%23a78bfa">
  <img alt="GitHub" src="https://img.shields.io/github/license/Var5h1l/KQLIntel?color=%23f472b6">
</p>

---

**KQLIntel** is a powerful, browser-based tool designed to bridge the gap between unstructured threat intelligence reports and actionable Kusto Query Language (KQL) queries. It leverages the power of modern Large Language Models (LLMs) to analyze threat reports from URLs or raw text, intelligently extract Indicators of Compromise (IOCs), and automatically generate KQL queries ready for threat hunting in Microsoft Sentinel and other security platforms.

The tool is designed for security analysts, threat hunters, and incident responders who need to quickly operationalize threat intelligence without manual parsing and query creation.

## ✨ Key Features

-   **Intelligent IOC Extraction:** Automatically identifies and extracts key IOCs, including IPs, domains, file hashes (MD5, SHA1, SHA256), filenames, and URLs.
-   **Automatic KQL Generation:** Instantly generates "guaranteed" KQL queries based on the extracted IOCs, ready to be used in your security tools.
-   **AI-Powered Enhancements:**
    -   **Threat Summaries:** Get a concise, AI-generated summary of the threat report.
    -   **Advanced Hunting Queries:** Discover deeper threats with experimental, AI-suggested hunting queries.
    -   **Mitigation Suggestions:** Receive actionable mitigation steps to respond to the identified threats.
-   **Flexible Input:** Analyze intelligence by providing a URL to a public report or by pasting in raw, unstructured text.
-   **Multi-Provider LLM Support:** Integrates with a wide range of LLM providers, including Google Gemini, OpenAI, Azure OpenAI, Anthropic, and any provider compatible with the OpenRouter API.
-   **Modern UI:** Features a sleek, user-friendly interface with both dark and light modes to suit your preference.
-   **Secure by Design:** API keys are stored securely in your browser's local storage and are never exposed or transmitted anywhere except to the respective AI provider's endpoint.

## 🚀 Live Demo & Screenshots

<b>1. URL / Threat Report Page</b>

<img width="1836" height="880" alt="image" src="https://github.com/user-attachments/assets/98c9fd3c-326c-4a12-8cba-9dd4d2aedcc1" />
<br></br>
<b>2. KQL Queries</b>
<br></br>

<img width="1872" height="880" alt="image" src="https://github.com/user-attachments/assets/9f45aadb-230e-48a1-8a44-fad415d1f072" />
<br></br>
<b>3. AI Generated Recommendations</b>
<br></br>
<img width="1851" height="807" alt="image" src="https://github.com/user-attachments/assets/2da910d1-43f5-40ae-ba87-ce612e36e89f" />
<br></br>
<b>4. API Configurations</b>
<br></br>
<img width="1086" height="832" alt="image" src="https://github.com/user-attachments/assets/865309ed-e733-4b40-8612-5d9a160b360d" />


## 🛠️ Getting Started

KQLIntel is a pure client-side application and requires no backend. You can run it locally or host it on any static web hosting service like GitHub Pages, Vercel, or Netlify.

### Prerequisites

-   A modern web browser (Chrome, Firefox, Edge, Safari).
-   An API key from a supported LLM provider (e.g., [Azure OpenAI](https://azure.microsoft.com/en-us/products/ai-services/openai-service) OR [Google AI Studio](https://aistudio.google.com/)), etc.
- 

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/KQLIntel.git](https://github.com/your-username/KQLIntel.git)
    ```
2.  **Navigate to the directory:**
    ```bash
    cd KQLIntel
    ```
3.  **Open `index.html`:**
    Simply open the `index.html` file in your local web browser to start using the application.

## ⚙️ How to Use

1.  **Set Your API Keys:**
    -   On first launch, click the **"Set API Keys"** button in the top-right corner.
    -   Enter the API key for the AI provider you wish to use.
    -   Click **"Save"**. Your key is saved securely in your browser's local storage for future use.

2.  **Choose an Input Method:**
    -   **URL:** Paste the URL of a public threat intelligence report. The tool will fetch and parse the content.
    -   **Raw Text:** Paste any unstructured text containing threat intelligence or IOCs directly into the text area.

3.  **Analyze the Intel:**
    -   Select your preferred AI Provider and Model from the dropdown menus.
    -   Click the **"Analyze & Generate KQL"** button.

4.  **Review the Results:**
    -   **Guaranteed KQL Queries:** The application will immediately display KQL queries based on the IOCs it confidently extracted.
    -   **AI Threat Summary:** Click "Generate Summary" to get a high-level overview of the threat.
    -   **AI-Assisted Hunting Queries:** Click "Suggest Advanced Queries" for more complex, behavior-based KQL queries.
    -   **Mitigation Suggestions:** After generating a summary, click "Suggest Mitigations" for recommended response actions.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please feel free to check the [issues page](https://github.com/your-username/KQLIntel/issues) to see if your idea has already been discussed.

## 👤 Author

-   **Varshil Desai**
-   **Connect:** [LinkedIn](https://www.linkedin.com/in/varshil01/)

## 📄 License

This project is open-source and available under the MIT License. See the [LICENSE](LICENSE) file for more info.
