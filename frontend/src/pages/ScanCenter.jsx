import { useState } from "react";
import { 
  analyzePhishing, analyzeImpersonation, analyzeSms, analyzeSocial,
  analyzeUrl, analyzeWebsite, analyzeDomainSpoof, analyzeLookalike, 
  analyzeSsl, analyzeUrlManipulation, analyzeRedirect, analyzeFakeLogin,
  analyzeDeepfake, analyzeQr
} from "../api";

export default function ScanCenter() {
  const [activeTab, setActiveTab] = useState("email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  // Tab 1 state
  const [textInput, setTextInput] = useState("");
  const [textType, setTextType] = useState("phishing");

  // Tab 2 state
  const [urlInput, setUrlInput] = useState("");
  const [urlChecks, setUrlChecks] = useState({
    url: true, website: false, domain: false, lookalike: false, ssl: false, manipulation: false, redirect: false, fakeLogin: false
  });

  // Tab 3 state
  const [fileInput, setFileInput] = useState(null);
  const [fileType, setFileType] = useState("deepfake");

  const getScoreColor = (score) => {
    if (score <= 30) return "bg-green-600";
    if (score <= 60) return "bg-yellow-500";
    if (score <= 79) return "bg-orange-500";
    return "bg-red-600";
  };

  const ResultCard = ({ res, title }) => (
    <div className="bg-gray-800 p-6 rounded-lg border border-gray-700 mt-6 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-semibold text-white">{title || "Analysis Result"}</h3>
        <span className={`px-3 py-1 rounded-full text-sm font-bold text-white ${getScoreColor(res.score)}`}>
          Score: {res.score}
        </span>
      </div>
      
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <span className="text-gray-400 text-sm">Verdict</span>
          <p className="text-lg text-white font-medium">{res.verdict}</p>
        </div>
        <div>
          <span className="text-gray-400 text-sm">Risk Level</span>
          <p className="text-lg text-white font-medium">{res.risk_level || res.riskLevel}</p>
        </div>
      </div>

      {(res.indicators && res.indicators.length > 0) && (
        <div className="mb-4">
          <span className="text-gray-400 text-sm">Indicators</span>
          <ul className="list-disc list-inside text-gray-200 mt-1">
            {res.indicators.map((ind, i) => (
              <li key={i}>{ind}</li>
            ))}
          </ul>
        </div>
      )}

      {res.recommended_action && (
        <div className="mb-4">
          <span className="text-gray-400 text-sm">Recommended Action</span>
          <p className="text-gray-200 mt-1">{res.recommended_action}</p>
        </div>
      )}

      <div className="text-xs text-gray-500 mt-4 text-right">
        Analyzed at: {new Date().toLocaleTimeString()}
      </div>
    </div>
  );

  const handleTextAnalyze = async () => {
    if (!textInput.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    let res;
    if (textType === "phishing") res = await analyzePhishing(textInput);
    else if (textType === "impersonation") res = await analyzeImpersonation(textInput);
    else if (textType === "sms") res = await analyzeSms(textInput);
    else if (textType === "social") res = await analyzeSocial(textInput);

    if (res?.error) setError(res.error);
    else setResult(res);
    setLoading(false);
  };

  const handleUrlAnalyze = async () => {
    if (!urlInput.trim()) return;
    setLoading(true);
    setResults([]);
    setError(null);
    
    const promises = [];
    if (urlChecks.url) promises.push(analyzeUrl(urlInput).then(r => ({ ...r, title: "URL Analysis" })));
    if (urlChecks.website) promises.push(analyzeWebsite(urlInput).then(r => ({ ...r, title: "Website Scan" })));
    if (urlChecks.domain) promises.push(analyzeDomainSpoof(urlInput).then(r => ({ ...r, title: "Domain Spoofing" })));
    if (urlChecks.lookalike) promises.push(analyzeLookalike(urlInput).then(r => ({ ...r, title: "Lookalike Domain" })));
    if (urlChecks.ssl) promises.push(analyzeSsl(urlInput).then(r => ({ ...r, title: "SSL Certificate" })));
    if (urlChecks.manipulation) promises.push(analyzeUrlManipulation(urlInput).then(r => ({ ...r, title: "URL Manipulation" })));
    if (urlChecks.redirect) promises.push(analyzeRedirect(urlInput).then(r => ({ ...r, title: "Redirect Chain" })));
    if (urlChecks.fakeLogin) promises.push(analyzeFakeLogin(urlInput).then(r => ({ ...r, title: "Fake Login Detection" })));

    const allRes = await Promise.all(promises);
    const errors = allRes.filter(r => r.error);
    if (errors.length === allRes.length && errors.length > 0) {
       setError("Failed to run URL scans");
    } else {
       setResults(allRes.filter(r => !r.error));
    }
    setLoading(false);
  };

  const handleFileAnalyze = async () => {
    if (!fileInput) return;
    setLoading(true);
    setResult(null);
    setError(null);
    
    let res;
    if (fileType === "deepfake") res = await analyzeDeepfake(fileInput);
    else if (fileType === "qr") res = await analyzeQr(fileInput);

    if (res?.error) setError(res.error);
    else setResult(res);
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 p-8 text-white">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8">Scan Center</h1>
        
        <div className="flex space-x-1 bg-gray-800 p-1 rounded-lg mb-8">
          <button 
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "email" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => setActiveTab("email")}
          >
            Email & Text
          </button>
          <button 
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "url" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => setActiveTab("url")}
          >
            URL & Website
          </button>
          <button 
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "file" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => setActiveTab("file")}
          >
            Media & Files
          </button>
        </div>

        {activeTab === "email" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">Text Analysis</h2>
            <select 
              value={textType}
              onChange={(e) => setTextType(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded p-3 mb-4 text-white"
            >
              <option value="phishing">Email Phishing</option>
              <option value="impersonation">Impersonation</option>
              <option value="sms">SMS / Smishing</option>
              <option value="social">Social Media Scam</option>
            </select>
            <textarea 
              className="w-full h-40 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-4 placeholder-gray-500"
              placeholder="Paste email body or message text here..."
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
            ></textarea>
            <button 
              onClick={handleTextAnalyze}
              disabled={loading || !textInput.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Analyze
            </button>
            {loading && <div className="mt-4 text-blue-400">Analyzing...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            {result && <ResultCard res={result} />}
          </div>
        )}

        {activeTab === "url" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">URL Analysis</h2>
            <input 
              type="text"
              className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-white mb-4 placeholder-gray-500"
              placeholder="https://example.com"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
            />
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {Object.keys(urlChecks).map(key => (
                <label key={key} className="flex items-center space-x-2 text-gray-300">
                  <input 
                    type="checkbox" 
                    checked={urlChecks[key]}
                    onChange={(e) => setUrlChecks({...urlChecks, [key]: e.target.checked})}
                    className="form-checkbox text-blue-600 rounded bg-gray-900 border-gray-600"
                  />
                  <span className="capitalize">{
                    key === "url" ? "URL Analysis" : 
                    key === "website" ? "Website Scan" : 
                    key === "domain" ? "Domain Spoofing" :
                    key === "lookalike" ? "Lookalike Domain" :
                    key === "ssl" ? "SSL Certificate" :
                    key === "manipulation" ? "URL Manipulation" :
                    key === "redirect" ? "Redirect Chain" :
                    key === "fakeLogin" ? "Fake Login Detection" : key
                  }</span>
                </label>
              ))}
            </div>

            <button 
              onClick={handleUrlAnalyze}
              disabled={loading || !urlInput.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Scan URL
            </button>
            {loading && <div className="mt-4 text-blue-400">Scanning...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            
            {results.map((res, i) => (
              <ResultCard key={i} res={res} title={res.title} />
            ))}
          </div>
        )}

        {activeTab === "file" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">File Analysis</h2>
            
            <div className="flex space-x-6 mb-6">
              <label className="flex items-center space-x-2 text-gray-300">
                <input 
                  type="radio" 
                  name="fileScanType"
                  value="deepfake"
                  checked={fileType === "deepfake"}
                  onChange={() => setFileType("deepfake")}
                  className="form-radio text-blue-600 bg-gray-900 border-gray-600"
                />
                <span>Deepfake Detection</span>
              </label>
              <label className="flex items-center space-x-2 text-gray-300">
                <input 
                  type="radio" 
                  name="fileScanType"
                  value="qr"
                  checked={fileType === "qr"}
                  onChange={() => setFileType("qr")}
                  className="form-radio text-blue-600 bg-gray-900 border-gray-600"
                />
                <span>QR Code Scan</span>
              </label>
            </div>

            <div className="border-2 border-dashed border-gray-600 rounded-lg p-10 text-center mb-6 hover:bg-gray-700 transition-colors">
              <input 
                type="file" 
                onChange={(e) => setFileInput(e.target.files[0])} 
                className="block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
              />
            </div>

            <button 
              onClick={handleFileAnalyze}
              disabled={loading || !fileInput}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Upload & Analyze
            </button>
            {loading && <div className="mt-4 text-blue-400">Analyzing file...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            {result && <ResultCard res={result} />}
          </div>
        )}
      </div>
    </div>
  );
}
