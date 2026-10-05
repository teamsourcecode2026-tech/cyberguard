import { useState } from "react";
import { 
  analyzePhishing, analyzeImpersonation, analyzeSms, analyzeSocial,
  analyzeUrl, analyzeWebsite, analyzeDomainSpoof, analyzeLookalike, 
  analyzeSsl, analyzeUrlManipulation, analyzeRedirect, analyzeFakeLogin,
  analyzeDeepfake, analyzeQr, analyzeMalware,
  analyzeNetworkTraffic, analyzeApiAbuse, analyzeSystemBehavior,
  analyzeExfiltration, analyzeUserActivity, analyzeInsiderThreat,
  analyzeEmailAuth
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

  // Tab 4 state
  const [networkType, setNetworkType] = useState("network_traffic");
  const [networkInput, setNetworkInput] = useState("");

  // Tab 5 state
  const [userType, setUserType] = useState("exfiltration");
  const [exfilInput, setExfilInput] = useState("");
  const [loginEventsInput, setLoginEventsInput] = useState("");
  const [actionEventsInput, setActionEventsInput] = useState("");
  const [insiderProfile, setInsiderProfile] = useState({
    user_id: "", department: "", is_resigning: false, resignation_date: "", recent_hr_incident: false, baseline_daily_actions: 0
  });
  const [insiderEventsInput, setInsiderEventsInput] = useState("");

  // Tab 6 state (Email Auth)
  const [emailAuthDomain, setEmailAuthDomain] = useState("");
  const [emailAuthIp, setEmailAuthIp] = useState("");
  const [dkimSelector, setDkimSelector] = useState("default");

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setResult(null);
    setResults([]);
    setError(null);
  };

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
    else if (fileType === "malware") res = await analyzeMalware(fileInput);

    if (res?.error) setError(res.error);
    else setResult(res);
    setLoading(false);
  };

  const handleNetworkAnalyze = async () => {
    if (!networkInput.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    
    try {
      const parsed = JSON.parse(networkInput);
      let res;
      if (networkType === "network_traffic") res = await analyzeNetworkTraffic(parsed);
      else if (networkType === "api_abuse") res = await analyzeApiAbuse(parsed);
      else if (networkType === "system_behavior") res = await analyzeSystemBehavior(parsed);

      if (res?.error) setError(res.error);
      else setResult(res);
    } catch (e) {
      setError("Invalid JSON format. Please check your input.");
    }
    setLoading(false);
  };

  const handleUserAnalyze = async () => {
    setLoading(true);
    setResult(null);
    setError(null);
    
    try {
      let res;
      if (userType === "exfiltration") {
        if (!exfilInput.trim()) { setLoading(false); return; }
        const parsed = JSON.parse(exfilInput);
        res = await analyzeExfiltration(parsed);
      } else if (userType === "user_activity") {
        if (!loginEventsInput.trim()) { setLoading(false); return; }
        const parsedLogins = JSON.parse(loginEventsInput);
        const parsedActions = actionEventsInput.trim() ? JSON.parse(actionEventsInput) : [];
        res = await analyzeUserActivity(parsedLogins, parsedActions);
      } else if (userType === "insider_threat") {
        if (!insiderEventsInput.trim()) { setLoading(false); return; }
        const parsedEvents = JSON.parse(insiderEventsInput);
        res = await analyzeInsiderThreat(insiderProfile, parsedEvents, insiderProfile.baseline_daily_actions);
      }

      if (res?.error) setError(res.error);
      else setResult(res);
    } catch (e) {
      setError("Invalid JSON format. Please check your input.");
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 p-8 text-white">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8">Scan Center</h1>
        
        <div className="flex space-x-1 bg-gray-800 p-1 rounded-lg mb-8 text-sm overflow-x-auto">
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "email" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("email")}
          >
            Email & Text
          </button>
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "url" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("url")}
          >
            URL & Website
          </button>
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "file" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("file")}
          >
            Media & Files
          </button>
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "network" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("network")}
          >
            Network & System
          </button>
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "user" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("user")}
          >
            User & Insider
          </button>
          <button 
            className={`flex-1 min-w-[120px] py-2 px-4 rounded-md font-medium transition-colors ${activeTab === "emailauth" ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}
            onClick={() => handleTabChange("emailauth")}
          >
            Email Auth
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
            <h2 className="text-xl font-semibold mb-4">Media & Files Analysis</h2>
            
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
              <label className="flex items-center space-x-2 text-gray-300">
                <input 
                  type="radio" 
                  name="fileScanType"
                  value="malware"
                  checked={fileType === "malware"}
                  onChange={() => setFileType("malware")}
                  className="form-radio text-blue-600 bg-gray-900 border-gray-600"
                />
                <span>Malware Scan</span>
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

        {activeTab === "network" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">Network & System Analysis</h2>
            <select 
              value={networkType}
              onChange={(e) => setNetworkType(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded p-3 mb-4 text-white"
            >
              <option value="network_traffic">Network Traffic</option>
              <option value="api_abuse">API Abuse</option>
              <option value="system_behavior">System Behavior</option>
            </select>
            <textarea 
              className="w-full h-40 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-2 placeholder-gray-500 font-mono text-sm"
              placeholder="Paste JSON data here..."
              value={networkInput}
              onChange={(e) => setNetworkInput(e.target.value)}
            ></textarea>
            <p className="text-xs text-gray-500 mb-4">
              {networkType === "network_traffic" && 'Format: [{"source_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "dest_port": 443, "data_transferred_mb": 5.0, "timestamp": "2026-10-05T10:00:00", "protocol": "TCP"}]'}
              {networkType === "api_abuse" && 'Format: [{"client_id": "user1", "endpoint": "/api/users", "method": "GET", "status_code": 200, "timestamp": "2026-10-05T10:00:00", "query_params": ""}]'}
              {networkType === "system_behavior" && 'Format: [{"event_type": "process_spawn", "parent_process": "word.exe", "child_process": "cmd.exe", "timestamp": "2026-10-05T10:00:00"}]'}
            </p>
            <button 
              onClick={handleNetworkAnalyze}
              disabled={loading || !networkInput.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Analyze
            </button>
            {loading && <div className="mt-4 text-blue-400">Analyzing...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            {result && <ResultCard res={result} />}
          </div>
        )}

        {activeTab === "user" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">User & Insider Analysis</h2>
            <select 
              value={userType}
              onChange={(e) => setUserType(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded p-3 mb-4 text-white"
            >
              <option value="exfiltration">Data Exfiltration</option>
              <option value="user_activity">User Activity</option>
              <option value="insider_threat">Insider Threat</option>
            </select>
            
            {userType === "exfiltration" && (
              <>
                <textarea 
                  className="w-full h-40 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-2 placeholder-gray-500 font-mono text-sm"
                  placeholder="Paste JSON data here..."
                  value={exfilInput}
                  onChange={(e) => setExfilInput(e.target.value)}
                ></textarea>
                <p className="text-xs text-gray-500 mb-4">
                  Format: {'[{"user_id": "john", "file_name": "passwords.csv", "action": "download", "size_mb": 50, "timestamp": "2026-10-05T10:00:00"}]'}
                </p>
              </>
            )}

            {userType === "user_activity" && (
              <>
                <textarea 
                  className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-2 placeholder-gray-500 font-mono text-sm"
                  placeholder="Paste login events JSON data here..."
                  value={loginEventsInput}
                  onChange={(e) => setLoginEventsInput(e.target.value)}
                ></textarea>
                <p className="text-xs text-gray-500 mb-4">
                  Format: {'[{"user_id": "john", "event_type": "login_failed", "timestamp": "2026-10-05T10:00:00"}]'}
                </p>
                <textarea 
                  className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-2 placeholder-gray-500 font-mono text-sm"
                  placeholder="Paste action events JSON data here (optional)..."
                  value={actionEventsInput}
                  onChange={(e) => setActionEventsInput(e.target.value)}
                ></textarea>
                <p className="text-xs text-gray-500 mb-4">
                  Format: {'[{"user_id": "john", "action": "delete_file", "timestamp": "2026-10-05T10:00:00"}]'}
                </p>
              </>
            )}

            {userType === "insider_threat" && (
              <>
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <input type="text" placeholder="User ID" className="bg-gray-900 border border-gray-700 rounded p-2 text-white" value={insiderProfile.user_id} onChange={(e) => setInsiderProfile({...insiderProfile, user_id: e.target.value})} />
                  <input type="text" placeholder="Department" className="bg-gray-900 border border-gray-700 rounded p-2 text-white" value={insiderProfile.department} onChange={(e) => setInsiderProfile({...insiderProfile, department: e.target.value})} />
                  <label className="flex items-center space-x-2 text-gray-300">
                    <input type="checkbox" className="form-checkbox text-blue-600 rounded bg-gray-900 border-gray-600" checked={insiderProfile.is_resigning} onChange={(e) => setInsiderProfile({...insiderProfile, is_resigning: e.target.checked})} />
                    <span>Is Resigning</span>
                  </label>
                  <input type="date" className="bg-gray-900 border border-gray-700 rounded p-2 text-white" value={insiderProfile.resignation_date} onChange={(e) => setInsiderProfile({...insiderProfile, resignation_date: e.target.value})} disabled={!insiderProfile.is_resigning} />
                  <label className="flex items-center space-x-2 text-gray-300">
                    <input type="checkbox" className="form-checkbox text-blue-600 rounded bg-gray-900 border-gray-600" checked={insiderProfile.recent_hr_incident} onChange={(e) => setInsiderProfile({...insiderProfile, recent_hr_incident: e.target.checked})} />
                    <span>Recent HR Incident</span>
                  </label>
                  <input type="number" placeholder="Baseline Daily Actions" className="bg-gray-900 border border-gray-700 rounded p-2 text-white" value={insiderProfile.baseline_daily_actions} onChange={(e) => setInsiderProfile({...insiderProfile, baseline_daily_actions: Number(e.target.value)})} />
                </div>
                <textarea 
                  className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-3 text-white mb-2 placeholder-gray-500 font-mono text-sm"
                  placeholder="Paste activity events JSON data here..."
                  value={insiderEventsInput}
                  onChange={(e) => setInsiderEventsInput(e.target.value)}
                ></textarea>
                <p className="text-xs text-gray-500 mb-4">
                  Format: {'[{"action": "download", "timestamp": "2026-10-05T10:00:00"}]'}
                </p>
              </>
            )}

            <button 
              onClick={handleUserAnalyze}
              disabled={loading || (userType === 'exfiltration' && !exfilInput.trim()) || (userType === 'user_activity' && !loginEventsInput.trim()) || (userType === 'insider_threat' && !insiderEventsInput.trim())}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Analyze
            </button>
            {loading && <div className="mt-4 text-blue-400">Analyzing...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            {result && <ResultCard res={result} />}
          </div>
        )}

        {activeTab === "emailauth" && (
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 className="text-xl font-semibold mb-2">Email Authentication Check</h2>
            <p className="text-gray-400 text-sm mb-6">Verify SPF, DKIM, and DMARC records for any email sender domain</p>
            
            <div className="space-y-4 mb-6">
              <div>
                <label className="text-gray-300 text-sm block mb-1">Sender Domain or Email *</label>
                <input 
                  type="text"
                  className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-white placeholder-gray-500"
                  placeholder="gmail.com or user@company.com"
                  value={emailAuthDomain}
                  onChange={(e) => setEmailAuthDomain(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-gray-300 text-sm block mb-1">Sender IP (optional)</label>
                  <input 
                    type="text"
                    className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-white placeholder-gray-500"
                    placeholder="e.g. 209.85.220.41"
                    value={emailAuthIp}
                    onChange={(e) => setEmailAuthIp(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-gray-300 text-sm block mb-1">DKIM Selector</label>
                  <input 
                    type="text"
                    className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-white placeholder-gray-500"
                    placeholder="default"
                    value={dkimSelector}
                    onChange={(e) => setDkimSelector(e.target.value)}
                  />
                </div>
              </div>
            </div>

            <button 
              onClick={async () => {
                if (!emailAuthDomain.trim()) return;
                setLoading(true);
                setResult(null);
                setError(null);
                const res = await analyzeEmailAuth(emailAuthDomain, emailAuthIp || null, dkimSelector || "default");
                if (res?.error) setError(res.error);
                else setResult(res);
                setLoading(false);
              }}
              disabled={loading || !emailAuthDomain.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded disabled:opacity-50"
            >
              Check Email Auth
            </button>
            {loading && <div className="mt-4 text-blue-400">Checking DNS records...</div>}
            {error && <div className="mt-4 text-red-500">{error}</div>}
            
            {result && (
              <>
                <ResultCard res={result} title="Email Authentication Result" />
                {result.spf && (
                  <div className="bg-gray-900 p-4 rounded-lg border border-gray-700 mt-3">
                    <h4 className="text-sm font-semibold text-gray-300 mb-2">📋 SPF Record</h4>
                    <p className="text-xs text-gray-400 break-all">{result.spf.record || "Not found"}</p>
                  </div>
                )}
                {result.dkim && (
                  <div className="bg-gray-900 p-4 rounded-lg border border-gray-700 mt-3">
                    <h4 className="text-sm font-semibold text-gray-300 mb-2">🔑 DKIM Record</h4>
                    <p className="text-xs text-gray-400 break-all">{result.dkim.record || "Not found"}</p>
                  </div>
                )}
                {result.dmarc && (
                  <div className="bg-gray-900 p-4 rounded-lg border border-gray-700 mt-3">
                    <h4 className="text-sm font-semibold text-gray-300 mb-2">🛡️ DMARC Record</h4>
                    <p className="text-xs text-gray-400 break-all">{result.dmarc.record || "Not found"}</p>
                    <p className="text-xs text-gray-500 mt-1">Policy: {result.dmarc.policy || "none"}</p>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
