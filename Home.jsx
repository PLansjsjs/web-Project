import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import './Home.css';

const Home = () => {
  const features = [
    {
      title: "Password Manager",
      description: "Securely store and manage all your passwords in one place",
      icon: "🔒",
      path: "/password-manager"
    },
    {
      title: "VirusTotal Scanner",
      description: "Scan files and URLs for malware using VirusTotal API",
      icon: "🛡️",
      path: "/virus-total"
    },
    {
      title: "Cyber Algorithm",
      description: "Step-by-step guide to protect against cyber attacks",
      icon: "📊",
      path: "/cyber-algorithm"
    },
    {
      title: "File Encrypter",
      description: "Encrypt and decrypt sensitive files with strong encryption",
      icon: "🔐",
      path: "/file-encrypter"
    }
  ];

  return (
    <div className="home">
      <motion.section 
        className="hero"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8 }}
      >
        <div className="hero-content">
          <motion.h1
            initial={{ y: -50 }}
            animate={{ y: 0 }}
            transition={{ type: 'spring', stiffness: 100 }}
          >
            Secure Your Digital Life
          </motion.h1>
          <motion.p
            initial={{ y: 50 }}
            animate={{ y: 0 }}
            transition={{ type: 'spring', stiffness: 100, delay: 0.1 }}
          >
            Comprehensive cybersecurity tools to protect your online presence
          </motion.p>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            <Link to="/cyber-algorithm" className="cta-button">
              Get Started
            </Link>
          </motion.div>
        </div>
      </motion.section>

      <section className="features">
        <h2>Our Security Tools</h2>
        <div className="features-grid">
          {features.map((feature, index) => (
            <motion.div 
              key={index}
              className="feature-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 + 0.3 }}
              whileHover={{ y: -10 }}
            >
              <div className="feature-icon">{feature.icon}</div>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
              <Link to={feature.path} className="feature-link">
                Explore →
              </Link>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="stats">
        <motion.div 
          className="stats-container"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
        >
          <div className="stat-item">
            <h3>10M+</h3>
            <p>Cyber attacks prevented</p>
          </div>
          <div className="stat-item">
            <h3>500K+</h3>
            <p>Users protected</p>
          </div>
          <div className="stat-item">
            <h3>99.9%</h3>
            <p>Security success rate</p>
          </div>
        </motion.div>
      </section>
    </div>
  );
};

export default Home;
