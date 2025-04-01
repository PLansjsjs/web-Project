import { useState } from 'react';
import { motion } from 'framer-motion';
import { Box, Typography, Stepper, Step, StepLabel, Button, Card, CardContent } from '@mui/material';
import { Lock, Security, Warning, VerifiedUser, Cloud, Email, Wifi, DeviceUnknown } from '@mui/icons-material';
import './CyberAlgorithm.css';

const steps = [
  { label: 'Identify', icon: <DeviceUnknown /> },
  { label: 'Protect', icon: <Lock /> },
  { label: 'Detect', icon: <Warning /> },
  { label: 'Respond', icon: <Security /> },
  { label: 'Recover', icon: <VerifiedUser /> }
];

const stepContent = [
  {
    title: 'Identify Potential Threats',
    items: [
      'Recognize phishing emails and suspicious links',
      'Identify vulnerable devices on your network',
      'Understand what sensitive data you need to protect',
      'Know which systems are critical for your operations'
    ],
    icon: <DeviceUnknown fontSize="large" />
  },
  {
    title: 'Protect Your Systems',
    items: [
      'Use strong, unique passwords and enable 2FA',
      'Keep all software updated with the latest patches',
      'Install and maintain antivirus/anti-malware software',
      'Use firewalls to protect your network',
      'Encrypt sensitive data'
    ],
    icon: <Lock fontSize="large" />
  },
  {
    title: 'Detect Security Incidents',
    items: [
      'Monitor for unusual account activity',
      'Watch for unexpected system behavior',
      'Set up alerts for suspicious network traffic',
      'Regularly review access logs',
      'Use intrusion detection systems'
    ],
    icon: <Warning fontSize="large" />
  },
  {
    title: 'Respond to Incidents',
    items: [
      'Isolate affected systems immediately',
      'Change all compromised credentials',
      'Notify appropriate personnel and authorities',
      'Document everything for post-incident review',
      'Preserve evidence for investigation'
    ],
    icon: <Security fontSize="large" />
  },
  {
    title: 'Recover and Improve',
    items: [
      'Restore systems from clean backups',
      'Conduct a post-incident analysis',
      'Update security policies based on lessons learned',
      'Provide additional training if needed',
      'Implement additional safeguards'
    ],
    icon: <VerifiedUser fontSize="large" />
  }
];

const threatScenarios = [
  {
    title: 'Phishing Attack',
    description: 'You receive an email that appears to be from your bank asking you to verify your account details.',
    steps: [
      'Do not click any links or download attachments',
      'Verify the email by contacting your bank directly',
      'Report the phishing attempt to your IT department',
      'If credentials were entered, change them immediately',
      'Enable multi-factor authentication if not already active'
    ],
    icon: <Email fontSize="large" />
  },
  {
    title: 'Ransomware Infection',
    description: 'Your files are encrypted and a ransom demand appears on your screen.',
    steps: [
      'Disconnect the infected device from the network',
      'Do not pay the ransom - it doesn\'t guarantee file recovery',
      'Report to your IT security team immediately',
      'Restore files from clean backups',
      'Identify how the malware entered your system to prevent recurrence'
    ],
    icon: <Cloud fontSize="large" />
  },
  {
    title: 'Wi-Fi Eavesdropping',
    description: 'You suspect someone is intercepting your data on a public Wi-Fi network.',
    steps: [
      'Disconnect from the network immediately',
      'Avoid accessing sensitive accounts on public Wi-Fi',
      'Use a VPN for all future public Wi-Fi connections',
      'Change passwords for any accounts accessed',
      'Monitor accounts for suspicious activity'
    ],
    icon: <Wifi fontSize="large" />
  }
];

const CyberAlgorithm = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [showScenarios, setShowScenarios] = useState(false);

  const handleNext = () => {
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const handleReset = () => {
    setActiveStep(0);
  };

  const toggleScenarios = () => {
    setShowScenarios(!showScenarios);
  };

  return (
    <motion.div 
      className="cyber-algorithm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="container">
        <Typography variant="h4" gutterBottom className="title">
          Cybersecurity Response Algorithm
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          A step-by-step guide to protect against and respond to cyber threats
        </Typography>

        <Box sx={{ width: '100%', margin: '2rem 0' }}>
          <Stepper activeStep={activeStep} alternativeLabel>
            {steps.map((step, index) => (
              <Step key={step.label}>
                <StepLabel icon={step.icon}>{step.label}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        {activeStep === steps.length ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="completion-message"
          >
            <Typography variant="h5" gutterBottom>
              You've completed the cybersecurity framework!
            </Typography>
            <Typography variant="body1" gutterBottom>
              Remember that cybersecurity is an ongoing process. Regularly review and update your security measures.
            </Typography>
            <Button onClick={handleReset} variant="contained" color="primary">
              Review Again
            </Button>
          </motion.div>
        ) : (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="step-content"
          >
            <Card className="step-card">
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  {stepContent[activeStep].icon}
                  <Typography variant="h5" component="div" ml={2}>
                    {stepContent[activeStep].title}
                  </Typography>
                </Box>
                
                <ul className="step-items">
                  {stepContent[activeStep].items.map((item, index) => (
                    <motion.li 
                      key={index}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      {item}
                    </motion.li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
              <Button
                variant="outlined"
                onClick={handleBack}
                disabled={activeStep === 0}
              >
                Back
              </Button>
              
              <Button 
                variant="contained" 
                onClick={handleNext}
              >
                {activeStep === steps.length - 1 ? 'Finish' : 'Next'}
              </Button>
            </Box>
          </motion.div>
        )}

        <Button 
          variant="text" 
          onClick={toggleScenarios}
          className="scenarios-toggle"
        >
          {showScenarios ? 'Hide Threat Scenarios' : 'Show Common Threat Scenarios'}
        </Button>

        {showScenarios && (
          <motion.div 
            className="threat-scenarios"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <Typography variant="h5" gutterBottom className="scenarios-title">
              Common Threat Scenarios
            </Typography>
            
            <div className="scenarios-grid">
              {threatScenarios.map((scenario, index) => (
                <Card key={index} className="scenario-card">
                  <CardContent>
                    <Box display="flex" alignItems="center" mb={2}>
                      {scenario.icon}
                      <Typography variant="h6" component="div" ml={2}>
                        {scenario.title}
                      </Typography>
                    </Box>
                    
                    <Typography variant="body1" mb={2}>
                      {scenario.description}
                    </Typography>
                    
                    <Typography variant="subtitle2" gutterBottom>
                      Response Steps:
                    </Typography>
                    
                    <ol className="scenario-steps">
                      {scenario.steps.map((step, stepIndex) => (
                        <li key={stepIndex}>{step}</li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
};

export default CyberAlgorithm;
