from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLabel, QLineEdit, QPushButton, QComboBox, 
                              QSpinBox, QCheckBox, QTabWidget, QTableWidget,
                              QTableWidgetItem, QTextEdit, QProgressBar,
                              QMessageBox, QFileDialog, QMenuBar, QMenu,
                              QAction, QGroupBox, QGridLayout, QRadioButton,
                              QButtonGroup, QStatusBar, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor

from core import ScannerManager, ConfigManager, ScanMode
from utils import VERSION, AUTHOR, TAGLINE, get_logger, ValidationHelper
from command import NmapCommandBuilder, CommandParser
from processing import ResultsParser
from reports import ReportGenerator
from update import UpdateManager

logger = get_logger("MainWindow")

class ScanWorkerThread(QThread):
    """Worker thread for executing scans"""
    
    # Signals
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, scanner_manager, config):
        super().__init__()
        self.scanner_manager = scanner_manager
        self.config = config
    
    def run(self):
        """Execute scan"""
        try:
            self.log_signal.emit(f"Starting {self.config.mode.value} scan on {self.config.target}...")
            
            # Execute scan
            if self.scanner_manager.execute_scan():
                results = self.scanner_manager.get_results()
                
                # Emit results
                for result in results:
                    self.result_signal.emit({
                        'port': result.port,
                        'service': result.service,
                        'state': result.state,
                        'version': result.version,
                    })
                
                # Generate insights
                insights = self.scanner_manager.generate_insights()
                self.log_signal.emit(f"Scan complete. Found {len(results)} open ports.")
                self.log_signal.emit(f"Risk Level: {insights.get('risk_level', 'Unknown').upper()}")
            else:
                self.error_signal.emit("Scan failed")
        
        except Exception as e:
            self.error_signal.emit(f"Scan error: {str(e)}")
            logger.error(f"Scan error: {e}")
        
        finally:
            self.finished_signal.emit()

class NetScanStudioUI(QMainWindow):
    """Main UI for NetScan Studio"""
    
    def __init__(self):
        try:
            super().__init__()
            self.setWindowTitle(f"NetScan Studio - {VERSION}")
            self.setGeometry(100, 100, 1400, 900)
            
            # Initialize managers
            self.scanner_manager = ScannerManager()
            self.config_manager = ConfigManager()
            self.report_generator = ReportGenerator()
            self.update_manager = UpdateManager()
            self.command_parser = CommandParser()
            
            # Scan state
            self.scan_thread = None
            self.is_scanning = False
            self.current_results = []
            self.current_config = None
            
            # Timer for updates (keep as instance variable to prevent garbage collection)
            self.update_timer = None
            
            self._build_ui()
            self._setup_menu()
            self._setup_styles()
            self._check_updates_on_startup()
        
        except Exception as e:
            logger.error(f"Failed to initialize NetScanStudioUI: {e}")
            raise
    
    def _build_ui(self):
        """Build UI components"""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()
        
        # --- Input Section ---
        input_group = self._create_input_panel()
        main_layout.addWidget(input_group)
        
        # --- Mode & Tool Selection ---
        mode_tool_group = self._create_mode_tool_panel()
        main_layout.addWidget(mode_tool_group)
        
        # --- Advanced Options (Collapsible) ---
        advanced_group = self._create_advanced_panel()
        main_layout.addWidget(advanced_group)
        
        # --- Command Preview ---
        command_group = self._create_command_panel()
        main_layout.addWidget(command_group)
        
        # --- Status & Progress ---
        status_group = self._create_status_panel()
        main_layout.addWidget(status_group)
        
        # --- Results Tabs ---
        results_group = self._create_results_panel()
        main_layout.addWidget(results_group, 1)
        
        # --- Action Buttons ---
        action_layout = QHBoxLayout()
        self.btn_start_scan = QPushButton("Start Scan")
        self.btn_stop_scan = QPushButton("Stop")
        self.btn_stop_scan.setEnabled(False)
        self.btn_clear = QPushButton("Clear Results")
        self.btn_export = QPushButton("Export Report")
        
        self.btn_start_scan.clicked.connect(self.start_scan)
        self.btn_stop_scan.clicked.connect(self.stop_scan)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_export.clicked.connect(self.export_report)
        
        action_layout.addWidget(self.btn_start_scan)
        action_layout.addWidget(self.btn_stop_scan)
        action_layout.addWidget(self.btn_clear)
        action_layout.addStretch()
        action_layout.addWidget(self.btn_export)
        
        main_layout.addLayout(action_layout)
        central.setLayout(main_layout)
        
        # Status bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")
    
    def _create_input_panel(self) -> QGroupBox:
        """Create target input panel"""
        group = QGroupBox("Target & Configuration")
        layout = QHBoxLayout()
        
        layout.addWidget(QLabel("Target (IP/Domain):"))
        self.input_target = QLineEdit()
        self.input_target.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        layout.addWidget(self.input_target, 2)
        
        layout.addWidget(QLabel("Common Ports:"))
        self.combo_ports = QComboBox()
        self.combo_ports.addItems([
            "Top 1000",
            "Top 100",
            "Custom",
        ])
        layout.addWidget(self.combo_ports)
        
        layout.addStretch()
        
        group.setLayout(layout)
        return group
    
    def _create_mode_tool_panel(self) -> QGroupBox:
        """Create mode and tool selection panel"""
        group = QGroupBox("Scan Mode & Tool Selection")
        layout = QHBoxLayout()
        
        # Mode selection
        layout.addWidget(QLabel("Mode:"))
        self.mode_group = QButtonGroup()
        for i, mode in enumerate(['Quick', 'Standard', 'Deep']):
            radio = QRadioButton(mode)
            if i == 0:
                radio.setChecked(True)
            radio.toggled.connect(self.on_mode_changed)
            self.mode_group.addButton(radio, i)
            layout.addWidget(radio)
        
        layout.addSpacing(20)
        
        # Tool selection
        layout.addWidget(QLabel("Tool:"))
        self.combo_tool = QComboBox()
        self.combo_tool.addItems(['socket', 'Nmap', 'Scapy'])
        self.combo_tool.currentTextChanged.connect(self.on_tool_changed)
        layout.addWidget(self.combo_tool)
        
        # Recommendation label
        self.label_recommendation = QLabel("[RECOMMENDED]")
        layout.addWidget(self.label_recommendation)
        
        layout.addStretch()
        
        group.setLayout(layout)
        return group
    
    def _create_advanced_panel(self) -> QGroupBox:
        """Create advanced options panel"""
        group = QGroupBox("Advanced Options (Nmap)")
        layout = QGridLayout()
        
        # Scan Type
        layout.addWidget(QLabel("Scan Type:"), 0, 0)
        self.combo_scan_type = QComboBox()
        self.combo_scan_type.addItems(['TCP Connect', 'SYN Scan', 'ACK Scan', 'UDP Scan', 'FIN Scan', 'Ping Scan'])
        self.combo_scan_type.setCurrentText('SYN Scan')
        layout.addWidget(self.combo_scan_type, 0, 1)
        
        # Host Discovery
        layout.addWidget(QLabel("Host Discovery:"), 0, 2)
        self.combo_host_discovery = QComboBox()
        self.combo_host_discovery.addItems(['Default', 'Skip Ping', 'Ping Scan Only'])
        layout.addWidget(self.combo_host_discovery, 0, 3)
        
        # Checkboxes for detection
        self.check_version = QCheckBox("Version Detection (-sV)")
        self.check_version.setChecked(True)
        layout.addWidget(self.check_version, 1, 0)
        
        self.check_os = QCheckBox("OS Detection (-O)")
        layout.addWidget(self.check_os, 1, 1)
        
        self.check_aggressive = QCheckBox("Aggressive Scan (-A)")
        layout.addWidget(self.check_aggressive, 1, 2)
        
        # Script selection
        self.check_scripts = QCheckBox("Enable Scripts")
        self.check_scripts.toggled.connect(self.on_scripts_toggled)
        layout.addWidget(self.check_scripts, 2, 0)
        
        self.combo_script_category = QComboBox()
        self.combo_script_category.addItems(['Vulnerability', 'Discovery', 'Safe', 'Auth'])
        self.combo_script_category.setEnabled(False)
        layout.addWidget(self.combo_script_category, 2, 1)
        
        self.combo_script = QComboBox()
        self.combo_script.setEnabled(False)
        layout.addWidget(self.combo_script, 2, 2)
        
        group.setLayout(layout)
        return group
    
    def _create_command_panel(self) -> QGroupBox:
        """Create command preview panel"""
        group = QGroupBox("Command Intelligence")
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Generated Command:"))
        
        h_layout = QHBoxLayout()
        self.input_command = QLineEdit()
        self.input_command.setReadOnly(True)
        h_layout.addWidget(self.input_command, 1)
        
        btn_copy = QPushButton("Copy")
        btn_copy.clicked.connect(self.copy_command)
        h_layout.addWidget(btn_copy)
        
        btn_edit = QPushButton("Edit")
        btn_edit.clicked.connect(self.edit_command)
        h_layout.addWidget(btn_edit)
        
        layout.addLayout(h_layout)
        
        self.label_command_status = QLabel("[OPTIMIZED]")
        layout.addWidget(self.label_command_status)
        
        group.setLayout(layout)
        return group
    
    def _create_status_panel(self) -> QGroupBox:
        """Create status and progress panel"""
        group = QGroupBox("Status")
        layout = QVBoxLayout()
        
        h_layout = QHBoxLayout()
        
        self.label_status = QLabel("Status: Ready")
        h_layout.addWidget(self.label_status)
        
        self.label_elapsed = QLabel("Elapsed: 0.00s")
        h_layout.addWidget(self.label_elapsed)
        
        layout.addLayout(h_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        group.setLayout(layout)
        return group
    
    def _create_results_panel(self) -> QTabWidget:
        """Create results tab widget"""
        tabs = QTabWidget()
        
        # Results Table Tab
        self.table_results = QTableWidget()
        self.table_results.setColumnCount(4)
        self.table_results.setHorizontalHeaderLabels(['Port', 'Service', 'State', 'Version'])
        tabs.addTab(self.table_results, "Results")
        
        # Insights Tab
        self.text_insights = QTextEdit()
        self.text_insights.setReadOnly(True)
        tabs.addTab(self.text_insights, "Insights")
        
        # Raw Output Tab
        self.text_raw = QTextEdit()
        self.text_raw.setReadOnly(True)
        tabs.addTab(self.text_raw, "Raw Output")
        
        # Report Tab
        self.text_report = QTextEdit()
        self.text_report.setReadOnly(True)
        tabs.addTab(self.text_report, "Report")
        
        return tabs
    
    def _setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        export_action = QAction("Export Report", self)
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        clear_action = QAction("Clear Results", self)
        clear_action.triggered.connect(self.clear_results)
        edit_menu.addAction(clear_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        check_update_action = QAction("Check for Updates", self)
        check_update_action.triggered.connect(self.check_updates)
        help_menu.addAction(check_update_action)
    
    def _setup_styles(self):
        """Setup UI styling"""
        # TryHackMe-inspired dark theme
        style = """
            QMainWindow { background-color: #1A1F2B; }
            QGroupBox { color: #EAEFF7; border: 1px solid #3A4358; border-radius: 5px; padding: 10px; }
            QLabel { color: #EAEFF7; }
            QLineEdit, QComboBox, QSpinBox, QTextEdit {
                background-color: #2A3142;
                color: #EAEFF7;
                border: 1px solid #3A4358;
                border-radius: 3px;
                padding: 5px;
            }
            QPushButton {
                background-color: #00C8FF;
                color: #1A1F2B;
                border: none;
                border-radius: 3px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #00B8E6; }
            QPushButton:pressed { background-color: #0098CC; }
            QPushButton:disabled { background-color: #6B7280; color: #B6C2D9; }
            QRadioButton { color: #EAEFF7; }
            QCheckBox { color: #EAEFF7; }
            QTabWidget { background-color: #1A1F2B; }
            QTabBar::tab { background-color: #222838; color: #EAEFF7; padding: 5px 15px; }
            QTabBar::tab:selected { background-color: #00C8FF; color: #1A1F2B; }
            QTableWidget { background-color: #2A3142; color: #EAEFF7; }
            QTableWidget::item { padding: 3px; }
            QProgressBar {
                background-color: #8892A6;
                border-radius: 3px;
            }
            QProgressBar::chunk { background-color: #7CFF6B; }
        """
        self.setStyleSheet(style)
    
    def on_mode_changed(self):
        """Handle mode change"""
        mode = self.mode_group.checkedButton().text()
        recommendation = self.scanner_manager.get_tool_recommendation(mode)
        
        # Set tool
        self.combo_tool.setCurrentText(recommendation['tool'])
        self.label_recommendation.setText(f"[{recommendation['status'].upper()}]")
        
        self.update_command_preview()
    
    def on_tool_changed(self):
        """Handle tool change"""
        mode = self.mode_group.checkedButton().text()
        recommendation = self.scanner_manager.get_tool_recommendation(mode)
        tool = self.combo_tool.currentText()
        
        if tool == recommendation['tool']:
            self.label_recommendation.setText(f"[{recommendation['status'].upper()}]")
        else:
            self.label_recommendation.setText(f"[MANUAL OVERRIDE]")
        
        self.update_command_preview()
    
    def on_scripts_toggled(self):
        """Handle scripts toggle"""
        enabled = self.check_scripts.isChecked()
        self.combo_script_category.setEnabled(enabled)
        self.combo_script.setEnabled(enabled)
    
    def update_command_preview(self):
        """Update command preview"""
        target = self.input_target.text()
        if not target:
            target = "192.168.1.1"
        
        builder = NmapCommandBuilder(target)
        builder.set_scan_type(self.combo_scan_type.currentText())
        builder.set_host_discovery(self.combo_host_discovery.currentText())
        
        if self.check_version.isChecked():
            builder.enable_version_detection()
        
        if self.check_os.isChecked():
            builder.enable_os_detection()
        
        if self.check_aggressive.isChecked():
            builder.enable_aggressive_scan()
        
        if self.check_scripts.isChecked() and self.combo_script.currentText():
            builder.set_script(self.combo_script.currentText())
        
        command = builder.build_command()
        self.input_command.setText(command)
    
    def copy_command(self):
        """Copy command to clipboard"""
        from PyQt5.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.input_command.text())
        QMessageBox.information(self, "Copied", "Command copied to clipboard")
    
    def edit_command(self):
        """Edit command manually"""
        self.input_command.setReadOnly(False)
        QMessageBox.information(self, "Edit Mode", "You can now edit the command. Press Enter when done.")
        self.input_command.setReadOnly(True)
    
    def start_scan(self):
        """Start scan"""
        target = self.input_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target")
            return
        
        # Verify target
        success, result = ValidationHelper.resolve_target(target)
        if not success:
            QMessageBox.warning(self, "Resolution Error", f"Failed to resolve target: {result}")
            return
        
        # Get configuration
        mode = self.mode_group.checkedButton().text()
        tool = self.combo_tool.currentText()
        
        # Create config
        config = self.scanner_manager.create_config(
            target=target,
            mode=mode,
            tool=tool,
            scan_type=self.combo_scan_type.currentText(),
            host_discovery=self.combo_host_discovery.currentText(),
            version_detection=self.check_version.isChecked(),
            os_detection=self.check_os.isChecked(),
            script=self.combo_script.currentText() if self.check_scripts.isChecked() else None,
        )
        
        self.current_config = config
        
        # Start scan in thread
        self.scan_thread = ScanWorkerThread(self.scanner_manager, config)
        self.scan_thread.log_signal.connect(self.add_log)
        self.scan_thread.result_signal.connect(self.add_result)
        self.scan_thread.error_signal.connect(self.on_scan_error)
        self.scan_thread.finished_signal.connect(self.on_scan_finished)
        
        self.is_scanning = True
        self.btn_start_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)
        self.label_status.setText("Status: Scanning...")
        
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop scan"""
        if self.scan_thread:
            self.scanner_manager.stop_scan()
            self.label_status.setText("Status: Stopped")
    
    def add_log(self, message):
        """Add log message"""
        self.text_raw.append(f"> {message}")
    
    def add_result(self, result):
        """Add result to table"""
        row = self.table_results.rowCount()
        self.table_results.insertRow(row)
        
        self.table_results.setItem(row, 0, QTableWidgetItem(str(result['port'])))
        self.table_results.setItem(row, 1, QTableWidgetItem(result['service']))
        self.table_results.setItem(row, 2, QTableWidgetItem(result['state']))
        self.table_results.setItem(row, 3, QTableWidgetItem(result['version'] or '-'))
        
        self.current_results = self.scanner_manager.get_results()
    
    def on_scan_error(self, error):
        """Handle scan error"""
        QMessageBox.critical(self, "Scan Error", error)
        self.label_status.setText(f"Status: Error - {error}")
    
    def on_scan_finished(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.btn_start_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        
        results = self.scanner_manager.get_results()
        insights = self.scanner_manager.generate_insights()
        
        # Show insights
        insights_text = f"""
Summary: {insights.get('summary', 'N/A')}
Risk Level: {insights.get('risk_level', 'Unknown').upper()}

Insights:
"""
        for insight in insights.get('insights', []):
            insights_text += f"• {insight}\n"
        
        insights_text += "\nRecommendations:\n"
        for rec in insights.get('recommendations', []):
            insights_text += f"• {rec}\n"
        
        self.text_insights.setText(insights_text)
        
        # Generate report
        report = self.report_generator.generate_txt_report(
            self.current_config.target,
            self.current_config.mode.value,
            self.current_config.tool,
            results,
            insights
        )
        self.text_report.setText(report)
        
        self.label_status.setText(f"Status: Completed - Found {len(results)} open ports")
    
    def clear_results(self):
        """Clear all results"""
        self.table_results.setRowCount(0)
        self.text_raw.clear()
        self.text_insights.clear()
        self.text_report.clear()
        self.current_results = []
        self.label_status.setText("Status: Ready")
    
    def export_report(self):
        """Export report to file"""
        if not self.current_results:
            QMessageBox.warning(self, "No Results", "No scan results to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "",
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filename:
            if filename.endswith('.json'):
                report = self.report_generator.generate_json_report(
                    self.current_config.target,
                    self.current_config.mode.value,
                    self.current_config.tool,
                    self.current_results,
                    self.scanner_manager.generate_insights()
                )
            elif filename.endswith('.csv'):
                report = self.report_generator.generate_csv_report(self.current_results)
            else:
                report = self.text_report.toPlainText()
            
            success, msg = self.report_generator.save_report(filename, report)
            if success:
                QMessageBox.information(self, "Success", msg)
            else:
                QMessageBox.critical(self, "Error", msg)
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
<h2>NetScan Studio</h2>
<p><b>{TAGLINE}</b></p>
<p>Version: {VERSION}</p>
<p>Author: {AUTHOR}</p>
<p>A comprehensive, intelligent network scanning platform
with multi-engine support and professional reporting.</p>
<p>
<b>Connect with me:</b><br>
<a href="https://linkedin.com/in/mr-sima">LinkedIn</a> | 
<a href="https://github.com/mr-simab">GitHub</a> | 
<a href="https://tryhackme.com/p/mrsima">TryHackMe</a>
</p>
"""
        msg = QMessageBox(self)
        msg.setWindowTitle("About NetScan Studio")
        msg.setText(about_text)
        msg.setTextFormat(Qt.RichText)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    
    def check_updates(self):
        """Check for updates"""
        update_available, message, release_info = self.update_manager.check_for_updates()
        
        if update_available:
            reply = QMessageBox.information(
                self,
                "Update Available",
                f"{message}\n\nWould you like to open the release page?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.update_manager.open_release_page()
        else:
            QMessageBox.information(self, "Updates", message)
    
    def _check_updates_on_startup(self):
        """Check for updates on startup"""
        self.update_timer = QTimer()
        self.update_timer.singleShot(2000, self.check_updates)
