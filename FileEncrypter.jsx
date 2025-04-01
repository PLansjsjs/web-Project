import { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Button, TextField, Card, CardContent, Typography, Box, Alert, IconButton } from '@mui/material';
import { LockOpen, Lock, FileUpload, FileDownload, Visibility, VisibilityOff, ContentCopy } from '@mui/icons-material';
import CryptoJS from 'crypto-js';
import { saveAs } from 'file-saver';
import './FileEncrypter.css';

const FileEncrypter = () => {
  const [file, setFile] = useState(null);
  const [password, setPassword] = useState('');
  const [action, setAction] = useState('encrypt');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const fileInputRef = useRef(null);
  const resultRef = useRef(null);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setResult(null);
      setError('');
    }
  };

  const handlePasswordChange = (e) => {
    setPassword(e.target.value);
  };

  const toggleAction = () => {
    setAction(action === 'encrypt' ? 'decrypt' : 'encrypt');
    setFile(null);
    setResult(null);
    setError('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const processFile = () => {
    if (!file) {
      setError('Please select a file');
      return;
    }
    if (!password) {
      setError('Please enter a password');
      return;
    }

    setError('');
    
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const fileData = e.target.result;
        
        if (action === 'encrypt') {
          // Encrypt the file
          const encryptedData = CryptoJS.AES.encrypt(fileData, password).toString();
          setResult({ type: 'encrypted', data: encryptedData });
        } else {
          // Decrypt the file
          try {
            const decryptedBytes = CryptoJS.AES.decrypt(fileData, password);
            const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);
            
            if (!decryptedData) {
              throw new Error('Invalid password or file format');
            }
            
            setResult({ type: 'decrypted', data: decryptedData });
          } catch (err) {
            setError('Failed to decrypt. Invalid password or corrupted file.');
          }
        }
      } catch (err) {
        setError('An error occurred during processing');
        console.error(err);
      }
    };
    
    if (action === 'encrypt') {
      reader.readAsDataURL(file);
    } else {
      reader.readAsText(file);
    }
  };

  const downloadResult = () => {
    if (!result) return;
    
    let blob, filename;
    
    if (result.type === 'encrypted') {
      blob = new Blob([result.data], { type: 'text/plain' });
      filename = `${file.name}.encrypted`;
    } else {
      // For decrypted files, we need to handle both text and binary data
      if (result.data.startsWith('data:')) {
        // It's a data URL (was originally a binary file)
        const byteString = atob(result.data.split(',')[1]);
        const mimeString = result.data.split(',')[0].split(':')[1].split(';')[0];
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        
        for (let i = 0; i < byteString.length; i++) {
          ia[i] = byteString.charCodeAt(i);
        }
        
        blob = new Blob([ab], { type: mimeString });
        filename = file.name.replace('.encrypted', '') || 'decrypted_file';
      } else {
        // It's plain text
        blob = new Blob([result.data], { type: 'text/plain' });
        filename = 'decrypted_text.txt';
      }
    }
    
    saveAs(blob, filename);
  };

  const copyToClipboard = () => {
    if (resultRef.current) {
      navigator.clipboard.writeText(resultRef.current.textContent);
      // You could add a toast notification here
    }
  };

  const isTextFile = file && file.type.startsWith('text/');

  return (
    <motion.div 
      className="file-encrypter"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="container">
        <Typography variant="h4" gutterBottom className="title">
          File {action === 'encrypt' ? 'Encrypter' : 'Decrypter'}
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          {action === 'encrypt' 
            ? 'Securely encrypt your files with AES-256 encryption' 
            : 'Decrypt your files using the correct password'}
        </Typography>

        <Card className="main-card">
          <CardContent>
            <Box display="flex" justifyContent="center" mb={3}>
              <Button 
                variant="contained" 
                onClick={toggleAction}
                startIcon={action === 'encrypt' ? <Lock /> : <LockOpen />}
                className="toggle-button"
              >
                Switch to {action === 'encrypt' ? 'Decryption' : 'Encryption'}
              </Button>
            </Box>

            <input
              type="file"
              onChange={handleFileChange}
              ref={fileInputRef}
              id="file-upload"
              style={{ display: 'none' }}
            />
            
            <label htmlFor="file-upload">
              <Button
                variant="outlined"
                component="span"
                fullWidth
                startIcon={<FileUpload />}
                className="upload-button"
              >
                {file ? file.name : 'Select File'}
              </Button>
            </label>

            <Box mt={3} className="password-field">
              <TextField
                fullWidth
                label={`Password to ${action}`}
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={handlePasswordChange}
                InputProps={{
                  endAdornment: (
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  )
                }}
              />
            </Box>

            {error && (
              <Alert severity="error" className="error-alert">
                {error}
              </Alert>
            )}

            <Box mt={3} display="flex" justifyContent="center">
              <Button
                variant="contained"
                color="primary"
                onClick={processFile}
                disabled={!file || !password}
                startIcon={action === 'encrypt' ? <Lock /> : <LockOpen />}
                className="process-button"
              >
                {action === 'encrypt' ? 'Encrypt File' : 'Decrypt File'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {result && (
          <motion.div 
            className="result-section"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <Card className="result-card">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {action === 'encrypt' ? 'Encryption Complete' : 'Decryption Complete'}
                </Typography>
                
                {result.type === 'encrypted' ? (
                  <>
                    <Typography variant="body1" gutterBottom>
                      Your file has been encrypted. Download the encrypted file or copy the encrypted text.
                    </Typography>
                    <div className="encrypted-text" ref={resultRef}>
                      {result.data}
                    </div>
                    <Box mt={2} display="flex" gap={2}>
                      <Button
                        variant="contained"
                        onClick={downloadResult}
                        startIcon={<FileDownload />}
                      >
                        Download Encrypted File
                      </Button>
                      {isTextFile && (
                        <Button
                          variant="outlined"
                          onClick={copyToClipboard}
                          startIcon={<ContentCopy />}
                        >
                          Copy Encrypted Text
                        </Button>
                      )}
                    </Box>
                  </>
                ) : (
                  <>
                    <Typography variant="body1" gutterBottom>
                      Your file has been decrypted. Download the decrypted file or view the contents below.
                    </Typography>
                    {result.data.startsWith('data:') ? (
                      <>
                        <Typography variant="body2" className="binary-message">
                          This is a binary file. Download to access the original content.
                        </Typography>
                        <Button
                          variant="contained"
                          onClick={downloadResult}
                          startIcon={<FileDownload />}
                          className="download-button"
                        >
                          Download Decrypted File
                        </Button>
                      </>
                    ) : (
                      <>
                        <div className="decrypted-text" ref={resultRef}>
                          {result.data}
                        </div>
                        <Box mt={2} display="flex" gap={2}>
                          <Button
                            variant="contained"
                            onClick={downloadResult}
                            startIcon={<FileDownload />}
                          >
                            Download as Text File
                          </Button>
                          <Button
                            variant="outlined"
                            onClick={copyToClipboard}
                            startIcon={<ContentCopy />}
                          >
                            Copy Text
                          </Button>
                        </Box>
                      </>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}

        <Card className="info-card" sx={{ mt: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Security Information
            </Typography>
            <Typography variant="body2">
              <strong>Encryption Method:</strong> AES-256 (Advanced Encryption Standard)
            </Typography>
            <Typography variant="body2" gutterBottom>
              <strong>Note:</strong> The security of your encrypted files depends entirely on the strength of your password. 
              Choose a strong, unique password and never share it. If you lose the password, 
              there is no way to recover the encrypted data.
            </Typography>
            <Typography variant="body2">
              <strong>Best Practices:</strong>
              <ul>
                <li>Use passwords with at least 12 characters</li>
                <li>Include uppercase, lowercase, numbers, and special characters</li>
                <li>Never reuse passwords across different files</li>
                <li>Store passwords securely using a password manager</li>
              </ul>
            </Typography>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
};

export default FileEncrypter;
