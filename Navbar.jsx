import { motion } from 'framer-motion';
import { NavLink } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldHalved, faLock, faVirus, faCode, faFileShield } from '@fortawesome/free-solid-svg-icons';
import './Navbar.css';

const Navbar = () => {
  const links = [
    { path: '/', name: 'Home', icon: faShieldHalved },
    { path: '/password-manager', name: 'Password Manager', icon: faLock },
    { path: '/virus-total', name: 'VirusTotal', icon: faVirus },
    { path: '/cyber-algorithm', name: 'Cyber Algorithm', icon: faCode },
    { path: '/file-encrypter', name: 'File Encrypter', icon: faFileShield },
  ];

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <motion.div 
          className="logo"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          CyberShield
        </motion.div>
        
        <ul className="nav-links">
          {links.map((link, index) => (
            <motion.li
              key={index}
              initial={{ y: -50, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: index * 0.1, type: 'spring', stiffness: 100 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <NavLink 
                to={link.path} 
                className={({ isActive }) => isActive ? 'active' : ''}
              >
                <FontAwesomeIcon icon={link.icon} className="nav-icon" />
                {link.name}
              </NavLink>
            </motion.li>
          ))}
        </ul>
      </div>
    </nav>
  );
};

export default Navbar;
