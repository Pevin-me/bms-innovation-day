#!/usr/bin/env python3
"""
BMS System Startup Script
"""
import os
import sys
import argparse
import logging
from app import app, socketio, init_db, logger

def setup_logging(log_level='INFO'):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('bms.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main startup function."""
    parser = argparse.ArgumentParser(description='BMS System')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Log level')
    parser.add_argument('--init-db', action='store_true', help='Initialize database only')
    parser.add_argument('--simulation', action='store_true', help='Force simulation mode')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Set environment variables
    if args.debug:
        os.environ['FLASK_DEBUG'] = 'True'
    if args.simulation:
        os.environ['SIMULATION_MODE'] = 'True'
    
    try:
        # Initialize database
        logger.info("Initializing database...")
        init_db()
        logger.info("Database initialized successfully")
        
        if args.init_db:
            logger.info("Database initialization complete. Exiting.")
            return
        
        # Start the application
        logger.info(f"Starting BMS System on {args.host}:{args.port}")
        logger.info(f"Debug mode: {args.debug}")
        logger.info(f"Simulation mode: {os.environ.get('SIMULATION_MODE', 'False')}")
        
        socketio.run(
            app, 
            host=args.host, 
            port=args.port, 
            debug=args.debug,
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
