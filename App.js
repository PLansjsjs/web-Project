import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import Navbar from './components/Navbar/Navbar';
import Footer from './components/Footer/Footer';
import Home from './pages/Home';
import PasswordManager from './pages/PasswordManager';
import VirusTotal from './pages/VirusTotal';
import CyberAlgorithm from './pages/CyberAlgorithm';
import FileEncrypter from './pages/FileEncrypter';
import './App.css';

function App() {
  return (
    <Router>
      <div className="app">
        <Navbar />
        <AnimatePresence mode="wait">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/password-manager" element={<PasswordManager />} />
            <Route path="/virus-total" element={<VirusTotal />} />
            <Route path="/cyber-algorithm" element={<CyberAlgorithm />} />
            <Route path="/file-encrypter" element={<FileEncrypter />} />
          </Routes>
        </AnimatePresence>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
