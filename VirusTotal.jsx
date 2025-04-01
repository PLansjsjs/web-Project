import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Box, Typography, Tabs, Tab, TextField, Button, 
  CircularProgress, Alert, Card, CardContent,
  IconButton, Tooltip, Divider, Chip
} from '@mui/material';
import { 
  CloudUpload, Search, History, Link, 
  Fingerprint, Storage, Dns, BatchPrediction,
  Info, Warning, CheckCircle, Cancel
} from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers';
import { Bar, Pie } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';
import { format, subDays } from 'date-fns';
import axios from 'axios';
import './VirusTotal.css';

Chart.register(...registerables);

const VirusTotal = () => {
  const [tabValue, setTabValue] = useState(0);
  const [apiKey, setApiKey] = useState(localStorage.getItem('virusTotalApiKey') || '');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanHistory, setScanHistory] = useState([]);
  
  // URL Scan State
  const [url, setUrl] = useState('');
  const [urlResult, setUrlResult] = useState(null);
  
  // File Scan State
  const [file, setFile] = useState(null);
  const [fileName, setFileName] = useState('');
  const [fileResult, setFileResult] = useState(null);
  
  // Hash Lookup State
  const [hash, setHash] = useState('');
  const [hashResult, setHashResult] = useState(null);
  
  // IP/Domain State
  const [ipOrDomain, setIpOrDomain] = useState('');
  const [ipDomainResult, setIpDomainResult] = useState(null);
  
  // Bulk Scan State
  const [bulkItems, setBulkItems] = useState('');
  const [bulkResults, setBulkResults] = useState([]);
  const [bulkProgress, setBulkProgress] = useState(0);
  
  // Date range for history
  const [dateRange, setDateRange] = useState([subDays(new Date(), 7), new Date()]);

  useEffect(() => {
    const history = JSON.parse(localStorage.getItem('vtScanHistory')) || [];
    setScanHistory(history);
  }, []);

  const handleApiKeyChange = (e) => {
    const newKey = e.target.value;
    setApiKey(newKey);
    localStorage.setItem('virusTotalApiKey', newKey);
  };

  const addToHistory = (type, resource, result) => {
    const newEntry = {
      id: Date.now(),
      type,
      resource,
      result: { data: { id: result.data.id } },
      date: new Date().toISOString()
    };
    
    const updatedHistory = [newEntry, ...scanHistory].slice(0, 50);
    setScanHistory(updatedHistory);
    localStorage.setItem('vtScanHistory', JSON.stringify(updatedHistory));
  };

  const scanUrl = async () => {
    if (!url) {
      setError('Please enter a URL to scan');
      return;
    }
    if (!apiKey) {
      setError('Please enter your VirusTotal API key');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      // Submit URL for scanning
      const scanResponse = await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        { url },
        { headers: { 'x-apikey': apiKey } }
      );

      // Get analysis report
      const reportResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${scanResponse.data.data.id}`,
        { headers: { 'x-apikey': apiKey } }
      );

      setUrlResult(reportResponse.data);
      addToHistory('url', url, scanResponse.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Failed to scan URL');
    } finally {
      setIsLoading(false);
    }
  };

  const scanFile = async () => {
    if (!file) {
      setError('Please select a file to scan');
      return;
    }
    if (!apiKey) {
      setError('Please enter your VirusTotal API key');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const formData = new FormData();
      formData.append('file', file);

      const uploadResponse = await axios.post(
        'https://www.virustotal.com/api/v3/files',
        formData,
        { headers: { 'x-apikey': apiKey } }
      );

      const reportResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${uploadResponse.data.data.id}`,
        { headers: { 'x-apikey': apiKey } }
      );

      setFileResult(reportResponse.data);
      addToHistory('file', fileName, uploadResponse.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Failed to scan file');
    } finally {
      setIsLoading(false);
    }
  };

  const lookupHash = async () => {
    if (!hash) {
      setError('Please enter a hash to lookup');
      return;
    }
    if (!apiKey) {
      setError('Please enter your VirusTotal API key');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        { headers: { 'x-apikey': apiKey } }
      );

      setHashResult(response.data);
      addToHistory('hash', hash, response.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Failed to lookup hash');
    } finally {
      setIsLoading(false);
    }
  };

  const checkIpDomain = async () => {
    if (!ipOrDomain) {
      setError('Please enter an IP or domain');
      return;
    }
    if (!apiKey) {
      setError('Please enter your VirusTotal API key');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/domains/${ipOrDomain}`,
        { headers: { 'x-apikey': apiKey } }
      );

      setIpDomainResult(response.data);
      addToHistory('domain', ipOrDomain, response.data);
    } catch (err) {
      // Try IP if domain fails
      try {
        const ipResponse = await axios.get(
          `https://www.virustotal.com/api/v3/ip_addresses/${ipOrDomain}`,
          { headers: { 'x-apikey': apiKey } }
        );
        setIpDomainResult(ipResponse.data);
        addToHistory('ip', ipOrDomain, ipResponse.data);
      } catch (ipErr) {
        setError('Failed to lookup IP/domain');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleBulkScan = async () => {
    if (!bulkItems) {
      setError('Please enter items to scan');
      return;
    }
    if (!apiKey) {
      setError('Please enter your VirusTotal API key');
      return;
    }

    const items = bulkItems.split('\n').filter(item => item.trim());
    if (items.length === 0) {
      setError('No valid items to scan');
      return;
    }

    setIsLoading(true);
    setError('');
    setBulkResults([]);
    setBulkProgress(0);
    
    try {
      const results = [];
      for (let i = 0; i < items.length; i++) {
        const item = items[i].trim();
        try {
          let result;
          if (item.startsWith('http')) {
            // URL scan
            const scanRes = await axios.post(
              'https://www.virustotal.com/api/v3/urls',
              { url: item },
              { headers: { 'x-apikey': apiKey } }
            );
            result = { type: 'url', item, status: 'completed', data: scanRes.data };
          } else if (item.length === 64 || item.length === 32 || item.length === 40) {
            // Hash lookup
            const hashRes = await axios.get(
              `https://www.virustotal.com/api/v3/files/${item}`,
              { headers: { 'x-apikey': apiKey } }
            );
            result = { type: 'hash', item, status: 'completed', data: hashRes.data };
          } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(item)) {
            // Domain lookup
            const domainRes = await axios.get(
              `https://www.virustotal.com/api/v3/domains/${item}`,
              { headers: { 'x-apikey': apiKey } }
            );
            result = { type: 'domain', item, status: 'completed', data: domainRes.data };
          } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(item)) {
            // IP lookup
            const ipRes = await axios.get(
              `https://www.virustotal.com/api/v3/ip_addresses/${item}`,
              { headers: { 'x-apikey': apiKey } }
            );
            result = { type: 'ip', item, status: 'completed', data: ipRes.data };
          } else {
            result = { type: 'unknown', item, status: 'error', error: 'Unsupported format' };
          }
          results.push(result);
        } catch (err) {
          results.push({ 
            type: 'error', 
            item, 
            status: 'error', 
            error: err.response?.data?.error?.message || 'Failed to scan' 
          });
        }
        setBulkProgress(((i + 1) / items.length) * 100);
        setBulkResults([...results]);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const renderScanResult = (result) => {
    if (!result) return null;
    
    const stats = result.data?.attributes?.stats || {};
    const totalEngines = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    const maliciousPercentage = totalEngines > 0 ? (stats.malicious / totalEngines) * 100 : 0;

    // Chart data
    const chartData = {
      labels: ['Malicious', 'Suspicious', 'Undetected', 'Harmless'],
      datasets: [{
        data: [stats.malicious || 0, stats.suspicious || 0, stats.undetected || 0, stats.harmless || 0],
        backgroundColor: [
          'rgba(255, 99, 132, 0.7)',
          'rgba(255, 206, 86, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(75, 192, 192, 0.7)'
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(255, 206, 86, 1)',
          'rgba(54, 162, 235, 1)',
          'rgba(75, 192, 192, 1)'
        ],
        borderWidth: 1
      }]
    };

    return (
      <Card className="result-card">
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">
              Scan Results
            </Typography>
            <Chip 
              label={maliciousPercentage > 10 ? 'Dangerous' : maliciousPercentage > 0 ? 'Suspicious' : 'Clean'}
              color={maliciousPercentage > 10 ? 'error' : maliciousPercentage > 0 ? 'warning' : 'success'}
              variant="outlined"
            />
          </Box>

          <Box display="flex" flexWrap="wrap" gap={4} mb={3}>
            <Box flex={1} minWidth={300}>
              <Typography variant="subtitle2" gutterBottom>
                Detection Stats
              </Typography>
              <Bar 
                data={chartData}
                options={{
                  responsive: true,
                  plugins: {
                    legend: { display: false }
                  }
                }}
              />
            </Box>
            <Box flex={1} minWidth={200}>
              <Typography variant="subtitle2" gutterBottom>
                Detection Ratio
              </Typography>
              <Pie 
                data={chartData}
                options={{
                  responsive: true,
                  plugins: {
                    legend: { position: 'right' }
                  }
                }}
              />
            </Box>
          </Box>

          {result.data?.attributes?.results && (
            <>
              <Typography variant="subtitle2" gutterBottom>
                Engine Details
              </Typography>
              <div className="engine-grid">
                {Object.entries(result.data.attributes.results).map(([engine, details]) => (
                  <div 
                    key={engine} 
                    className={`engine-card ${details.category === 'malicious' ? 'malicious' : 
                                 details.category === 'suspicious' ? 'suspicious' : ''}`}
                  >
                    <Box display="flex" justifyContent="space-between">
                      <Typography fontWeight="bold">{engine}</Typography>
                      {details.category === 'malicious' ? <Warning color="error" /> :
                       details.category === 'suspicious' ? <Warning color="warning" /> :
                       <CheckCircle color="success" />}
                    </Box>
                    <Typography variant="body2">Category: {details.category}</Typography>
                    {details.result && (
                      <Typography variant="body2">Result: {details.result}</Typography>
                    )}
                    {details.method && (
                      <Typography variant="body2">Method: {details.method}</Typography>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    );
  };

  return (
    <motion.div 
      className="virus-total"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="container">
        <Typography variant="h4" gutterBottom className="title">
          Enhanced VirusTotal Scanner
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          Comprehensive threat analysis for URLs, files, hashes, and IPs/Domains
        </Typography>

        <TextField
          fullWidth
          label="VirusTotal API Key"
          value={apiKey}
          onChange={handleApiKeyChange}
          margin="normal"
          type="password"
          helperText="Get your API key from VirusTotal website"
        />

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mt: 3 }}>
          <Tabs 
            value={tabValue} 
            onChange={(e, newValue) => setTabValue(newValue)}
            variant="scrollable"
            scrollButtons="auto"
          >
            <Tab label="URL Scan" icon={<Link />} />
            <Tab label="File Scan" icon={<CloudUpload />} />
            <Tab label="Hash Lookup" icon={<Fingerprint />} />
            <Tab label="IP/Domain" icon={<Dns />} />
            <Tab label="Bulk Scan" icon={<BatchPrediction />} />
            <Tab label="History" icon={<History />} />
          </Tabs>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ mt: 3 }}>
          {tabValue === 0 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <TextField
                fullWidth
                label="Enter URL to scan"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                margin="normal"
                placeholder="https://example.com"
                InputProps={{
                  startAdornment: <Link sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
              <Button
                variant="contained"
                onClick={scanUrl}
                disabled={isLoading}
                startIcon={isLoading ? <CircularProgress size={20} /> : <Search />}
                sx={{ mt: 2 }}
              >
                {isLoading ? 'Scanning...' : 'Scan URL'}
              </Button>
              {renderScanResult(urlResult)}
            </motion.div>
          )}

          {tabValue === 1 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <input
                accept="*"
                style={{ display: 'none' }}
                id="file-upload"
                type="file"
                onChange={(e) => {
                  setFile(e.target.files[0]);
                  setFileName(e.target.files[0]?.name || '');
                }}
              />
              <label htmlFor="file-upload">
                <Button
                  variant="outlined"
                  component="span"
                  fullWidth
                  startIcon={<CloudUpload />}
                  sx={{ mt: 2 }}
                >
                  {file ? fileName : 'Select File'}
                </Button>
              </label>
              {file && (
                <Button
                  variant="contained"
                  onClick={scanFile}
                  disabled={isLoading}
                  startIcon={isLoading ? <CircularProgress size={20} /> : <Search />}
                  sx={{ mt: 2 }}
                >
                  {isLoading ? 'Scanning...' : 'Scan File'}
                </Button>
              )}
              {renderScanResult(fileResult)}
            </motion.div>
          )}

          {tabValue === 2 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <TextField
                fullWidth
                label="Enter file hash (MD5, SHA-1, SHA-256)"
                value={hash}
                onChange={(e) => setHash(e.target.value)}
                margin="normal"
                placeholder="e.g., 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                InputProps={{
                  startAdornment: <Fingerprint sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
              <Button
                variant="contained"
                onClick={lookupHash}
                disabled={isLoading}
                startIcon={isLoading ? <CircularProgress size={20} /> : <Search />}
                sx={{ mt: 2 }}
              >
                {isLoading ? 'Looking up...' : 'Lookup Hash'}
              </Button>
              {renderScanResult(hashResult)}
            </motion.div>
          )}

          {tabValue === 3 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <TextField
                fullWidth
                label="Enter IP address or domain"
                value={ipOrDomain}
                onChange={(e) => setIpOrDomain(e.target.value)}
                margin="normal"
                placeholder="e.g., 8.8.8.8 or google.com"
                InputProps={{
                  startAdornment: <Dns sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
              <Button
                variant="contained"
                onClick={checkIpDomain}
                disabled={isLoading}
                startIcon={isLoading ? <CircularProgress size={20} /> : <Search />}
                sx={{ mt: 2 }}
              >
                {isLoading ? 'Checking...' : 'Check Reputation'}
              </Button>
              
              {ipDomainResult && (
                <Card sx={{ mt: 3 }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Reputation Analysis
                    </Typography>
                    <Typography variant="body1">
                      Last analysis: {new Date(ipDomainResult.data.attributes.last_analysis_date * 1000).toLocaleString()}
                    </Typography>
                    <Typography variant="body1" sx={{ mt: 1 }}>
                      Reputation: {ipDomainResult.data.attributes.reputation || 'N/A'}
                    </Typography>
                    
                    {ipDomainResult.data.attributes.last_analysis_stats && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2">Analysis Stats:</Typography>
                        <Box display="flex" gap={2} flexWrap="wrap">
                          <Chip label={`Harmless: ${ipDomainResult.data.attributes.last_analysis_stats.harmless}`} color="success" variant="outlined" />
                          <Chip label={`Malicious: ${ipDomainResult.data.attributes.last_analysis_stats.malicious}`} color="error" variant="outlined" />
                          <Chip label={`Suspicious: ${ipDomainResult.data.attributes.last_analysis_stats.suspicious}`} color="warning" variant="outlined" />
                          <Chip label={`Undetected: ${ipDomainResult.data.attributes.last_analysis_stats.undetected}`} variant="outlined" />
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              )}
            </motion.div>
          )}

          {tabValue === 4 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <TextField
                fullWidth
                label="Enter items to scan (one per line)"
                value={bulkItems}
                onChange={(e) => setBulkItems(e.target.value)}
                margin="normal"
                multiline
                rows={6}
                placeholder={`https://example.com\n8.8.8.8\ngoogle.com\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`}
              />
              <Button
                variant="contained"
                onClick={handleBulkScan}
                disabled={isLoading}
                startIcon={isLoading ? <CircularProgress size={20} /> : <BatchPrediction />}
                sx={{ mt: 2 }}
              >
                {isLoading ? `Scanning (${Math.round(bulkProgress)}%)` : 'Bulk Scan'}
              </Button>
              
              {bulkResults.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Bulk Scan Results
                  </Typography>
                  {bulkResults.map((result, index) => (
                    <Card key={index} sx={{ mb: 2 }}>
                      <CardContent>
                        <Box display="flex" justifyContent="space-between" alignItems="center">
                          <Typography fontWeight="bold">{result.item}</Typography>
                          {result.status === 'completed' ? (
                            <Chip 
                              label={result.data.data.attributes.stats.malicious > 0 ? 'Malicious' : 'Clean'}
                              color={result.data.data.attributes.stats.malicious > 0 ? 'error' : 'success'}
                              size="small"
                            />
                          ) : (
                            <Chip label="Error" color="error" size="small" />
                          )}
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          Type: {result.type}
                        </Typography>
                        {result.error && (
                          <Typography variant="body2" color="error">
                            Error: {result.error}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              )}
            </motion.div>
          )}

          {tabValue === 5 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <Box display="flex" gap={2} sx={{ mb: 3 }}>
                <DatePicker
                  label="From"
                  value={dateRange[0]}
                  onChange={(newValue) => setDateRange([newValue, dateRange[1]])}
                  maxDate={dateRange[1]}
                />
                <DatePicker
                  label="To"
                  value={dateRange[1]}
                  onChange={(newValue) => setDateRange([dateRange[0], newValue])}
                  minDate={dateRange[0]}
                />
              </Box>
              
              {scanHistory.length === 0 ? (
                <Typography variant="body1" sx={{ mt: 2 }}>
                  No scan history found
                </Typography>
              ) : (
                <Box sx={{ mt: 2 }}>
                  {scanHistory
                    .filter(item => {
                      const itemDate = new Date(item.date);
                      return itemDate >= dateRange[0] && itemDate <= dateRange[1];
                    })
                    .map((item) => (
                      <Card key={item.id} sx={{ mb: 2 }}>
                        <CardContent>
                          <Box display="flex" justifyContent="space-between">
                            <Box>
                              <Typography fontWeight="bold">
                                {item.type.toUpperCase()}: {item.resource}
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                {format(new Date(item.date), 'MMM d, yyyy HH:mm')}
                              </Typography>
                            </Box>
                            <Tooltip title="View details">
                              <IconButton onClick={() => {
                                if (item.type === 'url') {
                                  setUrl(item.resource);
                                  setUrlResult(item.result);
                                  setTabValue(0);
                                } else if (item.type === 'file') {
                                  setFileName(item.resource);
                                  setFileResult(item.result);
                                  setTabValue(1);
                                } else if (item.type === 'hash') {
                                  setHash(item.resource);
                                  setHashResult(item.result);
                                  setTabValue(2);
                                } else if (item.type === 'ip' || item.type === 'domain') {
                                  setIpOrDomain(item.resource);
                                  setIpDomainResult(item.result);
                                  setTabValue(3);
                                }
                              }}>
                                <Info />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </CardContent>
                      </Card>
                    ))}
                </Box>
              )}
            </motion.div>
          )}
        </Box>
      </div>
    </motion.div>
  );
};

export default VirusTotal;
