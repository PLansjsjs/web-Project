import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { TextField, Button, IconButton, Snackbar, Alert, Box, Typography } from '@mui/material';
import { Visibility, VisibilityOff, Delete, Edit, Add } from '@mui/icons-material';
import PasswordStrengthBar from 'react-password-strength-bar';
import CryptoJS from 'crypto-js';
import './PasswordManager.css';

const PasswordManager = () => {
  const [passwords, setPasswords] = useState([]);
  const [showPassword, setShowPassword] = useState(false);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');
  const [editingId, setEditingId] = useState(null);
  
  const [formData, setFormData] = useState({
    website: '',
    username: '',
    password: '',
    notes: ''
  });

  const encryptionKey = 'your-secure-encryption-key'; // In production, use a more secure method

  useEffect(() => {
    const savedPasswords = localStorage.getItem('encryptedPasswords');
    if (savedPasswords) {
      try {
        const bytes = CryptoJS.AES.decrypt(savedPasswords, encryptionKey);
        const decrypted = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        setPasswords(decrypted || []);
      } catch (error) {
        console.error('Failed to decrypt passwords', error);
        setPasswords([]);
      }
    }
  }, []);

  const savePasswords = (passwordsToSave) => {
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(passwordsToSave), 
      encryptionKey
    ).toString();
    localStorage.setItem('encryptedPasswords', encrypted);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!formData.website || !formData.username || !formData.password) {
      showAlert('Please fill all required fields', 'error');
      return;
    }

    if (editingId !== null) {
      // Update existing password
      const updatedPasswords = passwords.map(pwd => 
        pwd.id === editingId ? { ...formData, id: editingId } : pwd
      );
      setPasswords(updatedPasswords);
      savePasswords(updatedPasswords);
      showAlert('Password updated successfully', 'success');
      setEditingId(null);
    } else {
      // Add new password
      const newPassword = {
        ...formData,
        id: Date.now().toString()
      };
      const updatedPasswords = [...passwords, newPassword];
      setPasswords(updatedPasswords);
      savePasswords(updatedPasswords);
      showAlert('Password added successfully', 'success');
    }

    setFormData({
      website: '',
      username: '',
      password: '',
      notes: ''
    });
  };

  const handleEdit = (password) => {
    setFormData(password);
    setEditingId(password.id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleDelete = (id) => {
    const updatedPasswords = passwords.filter(pwd => pwd.id !== id);
    setPasswords(updatedPasswords);
    savePasswords(updatedPasswords);
    showAlert('Password deleted successfully', 'success');
    if (editingId === id) {
      setEditingId(null);
      setFormData({
        website: '',
        username: '',
        password: '',
        notes: ''
      });
    }
  };

  const showAlert = (message, severity) => {
    setSnackbarMessage(message);
    setSnackbarSeverity(severity);
    setOpenSnackbar(true);
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
  };

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    for (let i = 0; i < 16; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setFormData(prev => ({ ...prev, password }));
  };

  return (
    <motion.div 
      className="password-manager"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="container">
        <Typography variant="h4" gutterBottom className="title">
          Password Manager
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          Securely store and manage your passwords
        </Typography>

        <Box component="form" onSubmit={handleSubmit} className="form">
          <TextField
            fullWidth
            label="Website/App"
            name="website"
            value={formData.website}
            onChange={handleInputChange}
            margin="normal"
            required
          />
          
          <TextField
            fullWidth
            label="Username/Email"
            name="username"
            value={formData.username}
            onChange={handleInputChange}
            margin="normal"
            required
          />
          
          <div className="password-field">
            <TextField
              fullWidth
              label="Password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={handleInputChange}
              margin="normal"
              required
            />
            <IconButton
              onClick={() => setShowPassword(!showPassword)}
              edge="end"
              className="toggle-password"
            >
              {showPassword ? <VisibilityOff /> : <Visibility />}
            </IconButton>
          </div>
          
          {formData.password && (
            <PasswordStrengthBar password={formData.password} />
          )}
          
          <Button 
            variant="outlined" 
            onClick={generatePassword}
            startIcon={<Add />}
            className="generate-btn"
          >
            Generate Strong Password
          </Button>
          
          <TextField
            fullWidth
            label="Notes (Optional)"
            name="notes"
            value={formData.notes}
            onChange={handleInputChange}
            margin="normal"
            multiline
            rows={3}
          />
          
          <Button 
            type="submit" 
            variant="contained" 
            color="primary"
            className="submit-btn"
          >
            {editingId !== null ? 'Update Password' : 'Save Password'}
          </Button>
        </Box>

        {passwords.length > 0 ? (
          <div className="passwords-list">
            <Typography variant="h5" gutterBottom className="list-title">
              Your Saved Passwords
            </Typography>
            
            <div className="passwords-grid">
              {passwords.map((password) => (
                <motion.div 
                  key={password.id}
                  className="password-card"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  whileHover={{ scale: 1.02 }}
                >
                  <div className="card-header">
                    <h3>{password.website}</h3>
                    <div className="card-actions">
                      <IconButton onClick={() => handleEdit(password)}>
                        <Edit fontSize="small" />
                      </IconButton>
                      <IconButton onClick={() => handleDelete(password.id)}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </div>
                  </div>
                  
                  <p><strong>Username:</strong> {password.username}</p>
                  
                  <div className="password-display">
                    <span>{showPassword ? password.password : '••••••••'}</span>
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      size="small"
                    >
                      {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </div>
                  
                  {password.notes && (
                    <p className="notes"><strong>Notes:</strong> {password.notes}</p>
                  )}
                </motion.div>
              ))}
            </div>
          </div>
        ) : (
          <Typography variant="body1" className="empty-message">
            No passwords saved yet. Add your first password above.
          </Typography>
        )}
      </div>

      <Snackbar
        open={openSnackbar}
        autoHideDuration={3000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={handleCloseSnackbar} severity={snackbarSeverity}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </motion.div>
  );
};

export default PasswordManager;
