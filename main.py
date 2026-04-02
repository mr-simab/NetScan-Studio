#!/usr/bin/env python3
"""
NetScan Studio - Intelligent Network Scanning Platform
Scan smarter. Analyze deeper.

Author: Mr.Sima
Version: 1.0.0
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtCore import Qt

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import get_logger, VERSION, APP_NAME, AUTHOR
from setup import SetupHelper, DependencyManager
from ui import NetScanStudioUI

logger = get_logger("Main")

class SetupDialog(QWidget):
    """Setup/Dependency check dialog"""
    
    def __init__(self):
        super().__init__()
        self.setup_helper = SetupHelper()
        self.main_window = None  # Keep reference to main window
        self.init_ui()
    
    def init_ui(self):
        """Initialize setup UI"""
        self.setWindowTitle(f"{APP_NAME} - Setup")
        self.setGeometry(500, 300, 500, 300)
        
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel(f"<h2>{APP_NAME}</h2>"))
        layout.addWidget(QLabel("Checking dependencies..."))
        
        # Check dependencies
        status = self.setup_helper.get_setup_status()
        
        # Display status
        for name, installed in status['dependencies'].items():
            status_text = "[OK]" if installed else "[FAIL]"
            layout.addWidget(QLabel(f"{status_text} {name}"))
        
        layout.addStretch()
        
        # Action button
        if status['all_satisfied']:
            btn = QPushButton("Launch Application")
            btn.clicked.connect(self.launch_app)
            layout.addWidget(btn)
        else:
            layout.addWidget(QLabel("\n<b>Missing Dependencies Detected</b>"))
            
            missing_list = "<br>".join(status['missing'])
            layout.addWidget(QLabel(f"Missing: {missing_list}"))
            
            btn_auto = QPushButton("Install Python Packages")
            btn_auto.clicked.connect(self.install_packages)
            layout.addWidget(btn_auto)
            
            btn_manual = QPushButton("View Manual Installation Guide")
            btn_manual.clicked.connect(self.show_manual_guide)
            layout.addWidget(btn_manual)
            
            btn_skip = QPushButton("Continue Anyway (May not work)")
            btn_skip.clicked.connect(self.launch_app)
            layout.addWidget(btn_skip)
        
        self.setLayout(layout)
    
    def install_packages(self):
        """Install missing Python packages"""
        dep_manager = DependencyManager()
        success, message = dep_manager.install_python_packages()
        
        if success:
            QMessageBox.information(self, "Success", message)
            self.close()
            self.launch_app()
        else:
            QMessageBox.critical(self, "Installation Failed", message)
    
    def show_manual_guide(self):
        """Show manual installation guide"""
        dep_manager = DependencyManager()
        guide = dep_manager.get_installation_guide()
        QMessageBox.information(self, "Installation Guide", guide)
    
    def launch_app(self):
        """Launch main application"""
        self.close()
        # Create window and keep references to prevent garbage collection
        try:
            self.main_window = NetScanStudioUI()
            # Also store on QApplication to ensure it's not garbage collected
            QApplication.instance().main_window = self.main_window
            self.main_window.show()
        except Exception as e:
            logger.error(f"Failed to launch main window: {e}")
            QMessageBox.critical(None, "Launch Error", f"Failed to launch: {e}")
            sys.exit(1)

def main():
    """Main entry point"""
    logger.info(f"Starting {APP_NAME} v{VERSION}")
    logger.info(f"Author: {AUTHOR}")
    
    try:
        # Create Qt application
        app = QApplication(sys.argv)
        app.setStyleSheet("""
            QMessageBox {
                background-color: #1A1F2B;
            }
            QMessageBox QLabel {
                color: #EAEFF7;
                background-color: transparent;
            }
        """)
        
        # Show setup dialog and keep reference to prevent garbage collection
        setup_dialog = SetupDialog()
        setup_dialog.show()
        
        # Store references in app to prevent garbage collection
        app.setup_dialog = setup_dialog
        
        sys.exit(app.exec_())
    
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
