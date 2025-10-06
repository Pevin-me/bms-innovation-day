"""
Configuration file for BMS System
"""
import os
from datetime import timedelta

class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database settings
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'bms.db')
    
    # Sensor settings
    SENSOR_READ_INTERVAL = int(os.environ.get('SENSOR_READ_INTERVAL', '1'))  # seconds
    SERIAL_PORT = os.environ.get('SERIAL_PORT', None)  # e.g., 'COM3', '/dev/ttyUSB0'
    SERIAL_BAUD_RATE = int(os.environ.get('SERIAL_BAUD_RATE', '115200'))
    
    # Battery thresholds (configurable for different battery types)
    VOLTAGE_MIN = float(os.environ.get('VOLTAGE_MIN', '10.0'))  # Default for 12V+ systems
    VOLTAGE_MAX = float(os.environ.get('VOLTAGE_MAX', '14.4'))  # Default for 12V+ systems
    TEMP_MAX = float(os.environ.get('TEMP_MAX', '40.0'))
    SOC_MIN = float(os.environ.get('SOC_MIN', '20.0'))
    
    # Data retention
    DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', '30'))
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'bms.log')
    
    # Security
    SESSION_TIMEOUT = timedelta(hours=int(os.environ.get('SESSION_TIMEOUT_HOURS', '8')))
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    
    # Email settings (for alerts)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@bms.local')
    
    # System settings
    SYSTEM_NAME = os.environ.get('SYSTEM_NAME', 'BMS System')
    VERSION = os.environ.get('VERSION', '2.0')
    
    # Simulation settings
    SIMULATION_MODE = os.environ.get('SIMULATION_MODE', 'True').lower() == 'true'
    SIMULATION_BASE_VOLTAGE = float(os.environ.get('SIMULATION_BASE_VOLTAGE', '12.6'))  # 12V+ system
    SIMULATION_BASE_CURRENT = float(os.environ.get('SIMULATION_BASE_CURRENT', '5.0'))
    SIMULATION_BASE_TEMP = float(os.environ.get('SIMULATION_BASE_TEMP', '25.0'))
    SIMULATION_BASE_SOC = float(os.environ.get('SIMULATION_BASE_SOC', '75.0'))

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    SIMULATION_MODE = True

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    SIMULATION_MODE = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DATABASE_PATH = ':memory:'
    SIMULATION_MODE = True

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment."""
    env = os.environ.get('FLASK_ENV', 'default')
    return config.get(env, config['default'])
