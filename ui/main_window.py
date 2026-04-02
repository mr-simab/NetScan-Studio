from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLabel, QLineEdit, QPushButton, QComboBox, 
                              QCheckBox, QTabWidget, QTableWidget,
                              QTableWidgetItem, QTextEdit, QProgressBar,
                              QMessageBox, QFileDialog,
                              QAction, QGroupBox, QGridLayout, QRadioButton,
                              QButtonGroup, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import time

from core import ScannerManager, ConfigManager
from utils import VERSION, AUTHOR, TAGLINE, get_logger, ValidationHelper
from command import NmapCommandBuilder, CommandParser
from reports import ReportGenerator
from update import UpdateManager
from setup import platform_detector

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
        self._seen_results = set()
        self._last_error = None
    
    def run(self):
        """Execute scan"""
        try:
            self.log_signal.emit(f"Starting {self.config.mode.value} scan on {self.config.target}...")

            outcome = {'done': False, 'success': False}
            observed_engines = []

            def on_complete(success, _results):
                outcome['done'] = True
                outcome['success'] = success

            worker = self.scanner_manager.execute_scan_async(callback=on_complete)

            while worker.is_alive() or not outcome['done'] or self._pending_messages_exist(observed_engines):
                current_engine = self.scanner_manager.current_scan
                if current_engine and current_engine not in observed_engines:
                    observed_engines.append(current_engine)

                for engine in list(observed_engines):
                    self._drain_engine_messages(engine)

                self.msleep(50)

            for engine in list(observed_engines):
                self._drain_engine_messages(engine)

            results = self.scanner_manager.get_results()
            self._emit_missing_results(results)

            if outcome['success']:
                insights = self.scanner_manager.generate_insights()
                self.log_signal.emit(f"Scan complete. Found {len(results)} open ports.")
                self.log_signal.emit(f"Risk Level: {insights.get('risk_level', 'Unknown').upper()}")
            else:
                self.error_signal.emit(self._last_error or "Scan failed")
        
        except Exception as e:
            self.error_signal.emit(f"Scan error: {str(e)}")
            logger.error(f"Scan error: {e}")
        
        finally:
            self.finished_signal.emit()

    def _pending_messages_exist(self, engines):
        return any(not engine.result_queue.empty() for engine in engines if engine)

    def _drain_engine_messages(self, engine):
        for result_type, data in engine.get_pending_messages():
            if result_type == 'log':
                self.log_signal.emit(str(data))
            elif result_type == 'progress':
                self.progress_signal.emit(data.get('current', 0), data.get('total', 0))
            elif result_type == 'port_found':
                self._emit_result(data)
            elif result_type == 'error':
                self._last_error = str(data)
                self.log_signal.emit(f"[ERROR] {data}")

    def _emit_result(self, result):
        key = (result.port, result.service, result.state, result.version)
        if key in self._seen_results:
            return

        self._seen_results.add(key)
        self.result_signal.emit({
            'port': result.port,
            'service': result.service,
            'state': result.state,
            'version': result.version,
        })

    def _emit_missing_results(self, results):
        for result in results:
            self._emit_result(result)

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
            self.command_edit_mode = False
            self._current_progress_color = None
            self.scan_failed = False
            self.scan_stopped = False
            
            self._build_ui()
            self._connect_live_updates()
            self._refresh_script_options()
            self.on_mode_changed()
            self._setup_menu()
            self._setup_styles()
        
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

        self.input_custom_ports = QLineEdit()
        self.input_custom_ports.setPlaceholderText("Custom ports: 22,80,443 or 1-1024")
        self.input_custom_ports.setEnabled(False)
        layout.addWidget(self.input_custom_ports, 1)
        
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
        self.combo_tool.addItem('Socket', 'socket')
        self.combo_tool.addItem('Nmap', 'nmap')
        self.combo_tool.addItem('Scapy', 'scapy')
        self.combo_tool.addItem('Hybrid', 'hybrid')
        self.combo_tool.currentIndexChanged.connect(self.on_tool_changed)
        layout.addWidget(self.combo_tool)
        
        # Recommendation label
        self.label_recommendation = QLabel("[RECOMMENDED]")
        layout.addWidget(self.label_recommendation)
        
        layout.addStretch()
        
        group.setLayout(layout)
        return group
    
    def _create_advanced_panel(self) -> QGroupBox:
        """Create advanced options panel"""
        group = QGroupBox("Advanced Options")
        self.advanced_group = group
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

        layout.addWidget(QLabel("Scapy Analysis:"), 3, 0)
        self.combo_scapy_analysis = QComboBox()
        self.combo_scapy_analysis.addItem('TTL Analysis', 'ttl')
        self.combo_scapy_analysis.addItem('Firewall Detection', 'firewall')
        self.combo_scapy_analysis.addItem('Packet Crafting', 'packet')
        layout.addWidget(self.combo_scapy_analysis, 3, 1)
        
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
        
        self.btn_edit_command = QPushButton("Edit")
        self.btn_edit_command.clicked.connect(self.edit_command)
        h_layout.addWidget(self.btn_edit_command)
        
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
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("0%")
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
            QMessageBox {
                background-color: #1A1F2B;
            }
            QMessageBox QLabel {
                color: #EAEFF7;
                background-color: transparent;
            }
            QMessageBox QPushButton {
                min-width: 90px;
            }
        """
        app = QApplication.instance()
        if app:
            app.setStyleSheet(style)
        else:
            self.setStyleSheet(style)

    def _connect_live_updates(self):
        """Connect form fields to live preview updates"""
        self.input_target.textChanged.connect(self.update_command_preview)
        self.combo_ports.currentTextChanged.connect(self.on_port_selection_changed)
        self.input_custom_ports.textChanged.connect(self.update_command_preview)
        self.combo_scan_type.currentTextChanged.connect(self.update_command_preview)
        self.combo_host_discovery.currentTextChanged.connect(self.update_command_preview)
        self.check_version.toggled.connect(self.update_command_preview)
        self.check_os.toggled.connect(self.update_command_preview)
        self.check_aggressive.toggled.connect(self.update_command_preview)
        self.combo_script_category.currentTextChanged.connect(self.on_script_category_changed)
        self.combo_script.currentTextChanged.connect(self.update_command_preview)
        self.combo_scapy_analysis.currentIndexChanged.connect(self.update_command_preview)
        self.input_command.returnPressed.connect(self.apply_edited_command)

    def _current_mode(self) -> str:
        button = self.mode_group.checkedButton()
        return button.text() if button else 'Standard'

    def _current_tool(self) -> str:
        return self.combo_tool.currentData() or self.combo_tool.currentText().strip().lower()

    def _set_tool_selection(self, tool_name: str):
        idx = self.combo_tool.findData(tool_name)
        if idx >= 0:
            self.combo_tool.setCurrentIndex(idx)

    def _apply_mode_preset(self, mode: str):
        default_nmap_scan = 'SYN Scan' if platform_detector.supports_raw_packet_scans() else 'TCP Connect'

        if mode == 'Quick':
            self.combo_ports.setCurrentText('Top 1000')
            self.combo_scan_type.setCurrentText('TCP Connect')
            self.check_version.setChecked(False)
            self.check_os.setChecked(False)
            self.check_aggressive.setChecked(False)
        elif mode == 'Standard':
            self.combo_ports.setCurrentText('Top 1000')
            self.combo_scan_type.setCurrentText(default_nmap_scan)
            self.check_version.setChecked(True)
            self.check_os.setChecked(False)
            self.check_aggressive.setChecked(False)
        elif mode == 'Deep':
            self.combo_ports.setCurrentText('Top 1000')
            self.combo_scan_type.setCurrentText(default_nmap_scan)
            self.check_version.setChecked(True)
            self.check_os.setChecked(True)
            self.check_aggressive.setChecked(True)

    def _refresh_script_options(self):
        category = self.combo_script_category.currentText()
        scripts = NmapCommandBuilder.SCRIPTS_BY_CATEGORY.get(category, [])
        self.combo_script.blockSignals(True)
        self.combo_script.clear()
        for label, script_value in scripts:
            self.combo_script.addItem(label, script_value)
        self.combo_script.blockSignals(False)

    def _sync_advanced_controls(self):
        tool = self._current_tool()
        has_nmap_options = tool in {'nmap', 'hybrid'}
        has_scapy_options = tool in {'scapy', 'hybrid'}

        self.advanced_group.setTitle(f"Advanced Options ({tool.title()})")

        nmap_widgets = [
            self.combo_scan_type,
            self.combo_host_discovery,
            self.check_version,
            self.check_os,
            self.check_aggressive,
            self.check_scripts,
        ]

        for widget in nmap_widgets:
            widget.setEnabled(has_nmap_options)

        self.combo_script_category.setEnabled(has_nmap_options and self.check_scripts.isChecked())
        self.combo_script.setEnabled(has_nmap_options and self.check_scripts.isChecked())
        self.combo_scapy_analysis.setEnabled(has_scapy_options)
        self.btn_edit_command.setEnabled(tool == 'nmap')

        if tool != 'nmap' and self.command_edit_mode:
            self.command_edit_mode = False
            self.input_command.setReadOnly(True)
            self.btn_edit_command.setText("Edit")

    def _selected_ports_config(self):
        selection = self.combo_ports.currentText()
        if selection == 'Custom':
            return self.input_custom_ports.text().strip() or None, None
        return None, selection

    def _build_current_config(self, target_override: str = None):
        target = target_override or self.input_target.text().strip() or "192.168.1.1"
        ports, port_strategy = self._selected_ports_config()

        script_value = None
        if self.check_scripts.isChecked() and self.combo_script.count():
            script_value = self.combo_script.currentData() or self.combo_script.currentText()

        return self.scanner_manager.create_config(
            target=target,
            mode=self._current_mode(),
            tool=self._current_tool(),
            scan_type=self.combo_scan_type.currentText(),
            host_discovery=self.combo_host_discovery.currentText(),
            version_detection=self.check_version.isChecked(),
            os_detection=self.check_os.isChecked(),
            aggressive=self.check_aggressive.isChecked(),
            script=script_value,
            ports=ports,
            port_strategy=port_strategy,
            scapy_analysis=self.combo_scapy_analysis.currentData(),
        )

    def on_mode_changed(self, *_):
        """Handle mode change"""
        mode = self._current_mode()
        recommendation = self.scanner_manager.get_tool_recommendation(mode)

        self._apply_mode_preset(mode)
        self._set_tool_selection(recommendation['tool'])
        self.label_recommendation.setText(f"[{recommendation['status'].upper()}]")

        self._sync_advanced_controls()
        self.update_command_preview()

    def on_tool_changed(self, *_):
        """Handle tool change"""
        mode = self._current_mode()
        recommendation = self.scanner_manager.get_tool_recommendation(mode)
        tool = self._current_tool()

        if tool == recommendation['tool']:
            self.label_recommendation.setText(f"[{recommendation['status'].upper()}]")
        else:
            self.label_recommendation.setText("[MANUAL OVERRIDE]")

        self._sync_advanced_controls()
        self.update_command_preview()

    def on_port_selection_changed(self, *_):
        """Handle common port profile changes"""
        is_custom = self.combo_ports.currentText() == 'Custom'
        self.input_custom_ports.setEnabled(is_custom)
        if not is_custom:
            self.input_custom_ports.clear()
        self.update_command_preview()

    def on_script_category_changed(self, *_):
        """Refresh scripts when the category changes"""
        self._refresh_script_options()
        self.update_command_preview()

    def on_scripts_toggled(self, *_):
        """Handle scripts toggle"""
        enabled = self.check_scripts.isChecked() and self._current_tool() in {'nmap', 'hybrid'}
        self.combo_script_category.setEnabled(enabled)
        self.combo_script.setEnabled(enabled)
        if enabled:
            self._refresh_script_options()
        self.update_command_preview()

    def update_command_preview(self, *_):
        """Update command preview"""
        if self.command_edit_mode:
            return

        tool = self._current_tool()
        status_map = {
            'socket': '[SOCKET ENGINE PREVIEW]',
            'nmap': '[CLI COMMAND]',
            'scapy': '[SCAPY ENGINE PREVIEW]',
            'hybrid': '[HYBRID PIPELINE PREVIEW]',
        }

        try:
            self._build_current_config()
            command = self.scanner_manager.generate_command_preview()
            self.input_command.setText(command)
            status_text = status_map.get(tool, '[PREVIEW]')
            compatibility_note = self.scanner_manager.get_compatibility_note()
            if compatibility_note:
                status_text = f"{status_text} [SAFE FALLBACK]"
            self.label_command_status.setText(status_text)
        except ValueError as exc:
            self.input_command.setText("Invalid custom ports. Use formats like 22,80,443 or 1-1024.")
            self.label_command_status.setText("[INVALID PORTS]")
            logger.debug(f"Command preview skipped: {exc}")
    
    def copy_command(self):
        """Copy command to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.input_command.text())
        QMessageBox.information(self, "Copied", "Command copied to clipboard")
    
    def edit_command(self):
        """Edit command manually"""
        if self._current_tool() != 'nmap':
            QMessageBox.information(self, "Edit Unavailable", "Manual command editing is only available for direct Nmap scans.")
            return

        if self.command_edit_mode:
            self.apply_edited_command()
            return

        self.command_edit_mode = True
        self.input_command.setReadOnly(False)
        self.input_command.setFocus()
        self.input_command.selectAll()
        self.btn_edit_command.setText("Apply")
        self.label_command_status.setText("[EDITING NMAP COMMAND]")

    def apply_edited_command(self):
        """Apply a manually edited Nmap command back to the UI"""
        if not self.command_edit_mode:
            return

        command = self.input_command.text().strip()
        if not self.command_parser.is_valid_nmap_command(command):
            QMessageBox.warning(self, "Invalid Command", "Enter a valid Nmap command before applying it.")
            return

        parsed = self.command_parser.parse_nmap_command(command)

        if parsed.get('target'):
            self.input_target.setText(parsed['target'])

        if parsed.get('scan_type'):
            self.combo_scan_type.setCurrentText(parsed['scan_type'])

        if parsed.get('host_discovery'):
            self.combo_host_discovery.setCurrentText(parsed['host_discovery'])
        else:
            self.combo_host_discovery.setCurrentText('Default')

        self.check_version.setChecked(parsed.get('version_detection', False))
        self.check_os.setChecked(parsed.get('os_detection', False))
        self.check_aggressive.setChecked(parsed.get('aggressive', False))

        port_strategy = parsed.get('port_strategy')
        if parsed.get('ports'):
            self.combo_ports.setCurrentText('Custom')
            self.input_custom_ports.setText(parsed['ports'])
        elif port_strategy in {'Top 100', 'Top 1000'}:
            self.combo_ports.setCurrentText(port_strategy)
        else:
            self.combo_ports.setCurrentText('Top 1000')

        script_value = parsed.get('script')
        self.check_scripts.setChecked(bool(script_value))
        if script_value:
            for category, scripts in NmapCommandBuilder.SCRIPTS_BY_CATEGORY.items():
                if any(value == script_value for _, value in scripts):
                    self.combo_script_category.setCurrentText(category)
                    break
            found = self.combo_script.findData(script_value)
            if found >= 0:
                self.combo_script.setCurrentIndex(found)

        self.command_edit_mode = False
        self.input_command.setReadOnly(True)
        self.btn_edit_command.setText("Edit")
        self.update_command_preview()
    
    def start_scan(self):
        """Start scan"""
        if self.command_edit_mode:
            self.apply_edited_command()
            if self.command_edit_mode:
                return

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
        try:
            config = self._build_current_config(target)
            self.scanner_manager.generate_command_preview()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Ports", str(exc))
            return

        compatibility_note = self.scanner_manager.get_compatibility_note()
        if compatibility_note:
            self.text_raw.append(f"> [Compatibility] {compatibility_note}")
        
        self.current_config = config
        
        # Start scan in thread
        self.scan_thread = ScanWorkerThread(self.scanner_manager, config)
        self.scan_thread.log_signal.connect(self.handle_scan_log)
        self.scan_thread.result_signal.connect(self.add_result)
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.error_signal.connect(self.on_scan_error)
        self.scan_thread.finished_signal.connect(self.on_scan_finished)
        
        self.is_scanning = True
        self.scan_failed = False
        self.scan_stopped = False
        self.btn_start_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)
        self._reset_runtime_views()
        self._set_progress_style("#00C8FF")
        self.label_status.setText("Status: Scanning...")
        self.statusbar.showMessage(f"Scanning {target}...")
        
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop scan"""
        if self.scan_thread:
            self.scan_stopped = True
            self.scanner_manager.stop_scan()
            self.label_status.setText("Status: Stopped")
            self.statusbar.showMessage("Scan stopped")
            self._set_progress_style("#FFB020")
    
    def handle_scan_log(self, message):
        """Add log message and keep the status section current."""
        self.text_raw.append(f"> {message}")
        self.statusbar.showMessage(message)
        self._update_elapsed_label()

        lowered = message.lower()
        if "starting" in lowered or "running:" in lowered or "analysis started" in lowered:
            self.label_status.setText(f"Status: {message}")
        elif "completed" in lowered or "scan complete" in lowered:
            self.label_status.setText(f"Status: {message}")
    
    def add_result(self, result):
        """Add result to table"""
        row = self.table_results.rowCount()
        self.table_results.insertRow(row)
        
        self.table_results.setItem(row, 0, QTableWidgetItem(str(result['port'])))
        self.table_results.setItem(row, 1, QTableWidgetItem(result['service']))
        self.table_results.setItem(row, 2, QTableWidgetItem(result['state']))
        self.table_results.setItem(row, 3, QTableWidgetItem(result['version'] or '-'))
        
        self.current_results = self.scanner_manager.get_results()

    def update_progress(self, current, total):
        """Update progress bar with live engine progress."""
        total = max(total, 1)
        current = min(max(current, 0), total)
        percent = int((current / total) * 100)

        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"{percent}% ({current}/{total})")
        self.label_status.setText(f"Status: Scanning... {current}/{total}")
        self.statusbar.showMessage(f"Progress {percent}% ({current}/{total})")
        self._update_elapsed_label()
    
    def on_scan_error(self, error):
        """Handle scan error"""
        self.scan_failed = True
        QMessageBox.critical(self, "Scan Error", error)
        self.label_status.setText(f"Status: Error - {error}")
        self.statusbar.showMessage(error)
        self._set_progress_style("#FF5C7A")
    
    def on_scan_finished(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.btn_start_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        
        results = self.scanner_manager.get_results()
        insights = self.scanner_manager.generate_insights()
        self._render_results_table(results)
        self._update_elapsed_label()
        
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

        if self.scan_failed:
            self.label_status.setText("Status: Failed")
            self.statusbar.showMessage("Scan failed")
            self.progress_bar.setFormat(self.progress_bar.format() or "Failed")
            self._set_progress_style("#FF5C7A")
            return

        if self.scan_stopped:
            self.label_status.setText("Status: Stopped")
            self.statusbar.showMessage("Scan stopped")
            self.progress_bar.setFormat(self.progress_bar.format() or "Stopped")
            self._set_progress_style("#FFB020")
            return

        if self.progress_bar.value() < 100:
            self.progress_bar.setValue(100)
        self.progress_bar.setFormat(f"100% ({len(results)} open ports)")
        self._set_progress_style("#7CFF6B")
        self.label_status.setText(f"Status: Completed - Found {len(results)} open ports")
        self.statusbar.showMessage(f"Completed: {len(results)} open ports found")
    
    def clear_results(self):
        """Clear all results"""
        self.table_results.setRowCount(0)
        self.text_raw.clear()
        self.text_insights.clear()
        self.text_report.clear()
        self.current_results = []
        self.label_status.setText("Status: Ready")
        self.label_elapsed.setText("Elapsed: 0.00s")
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0%")
        self._set_progress_style("#7CFF6B")
        self.statusbar.showMessage("Ready")
    
    def export_report(self):
        """Export report to file"""
        if not self.current_results:
            QMessageBox.warning(self, "No Results", "No scan results to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            self.report_generator.generate_filename(self.current_config.target, "txt"),
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

        if not update_available:
            QMessageBox.information(self, "Updates", message)
            return

        selected_asset = release_info.get("selected_asset") if release_info else None

        if not selected_asset:
            reply = QMessageBox.question(
                self,
                "Update Available",
                f"{message}\n\nOpen the release page to review the release manually?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.update_manager.open_release_page()
            return

        reply = QMessageBox.question(
            self,
            "Update Available",
            (
                f"{message}\n\n"
                f"Selected package: {selected_asset.get('name', 'Unknown package')}\n\n"
                "Do you want to download and prepare this update now?\n"
                "Choose 'No' to open the release page instead."
            ),
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
        )

        if reply == QMessageBox.No:
            self.update_manager.open_release_page()
            return

        if reply != QMessageBox.Yes:
            return

        success, prepare_message, prepared_update = self.update_manager.prepare_update()
        if not success:
            QMessageBox.critical(self, "Update Error", prepare_message)
            return

        install_ready = prepared_update.get("install_ready", False)
        install_note = prepared_update.get("install_note", "")
        staged_path = prepared_update.get("staging_dir", "")

        if not install_ready:
            QMessageBox.information(
                self,
                "Update Prepared",
                (
                    f"{prepare_message}\n\n"
                    f"Staged at:\n{staged_path}\n\n"
                    f"{install_note}"
                )
            )
            return

        install_reply = QMessageBox.question(
            self,
            "Install Update",
            (
                f"{prepare_message}\n\n"
                f"Staged at:\n{staged_path}\n\n"
                "Install this update now?\n"
                "NetScan Studio will close so the files can be replaced."
            ),
            QMessageBox.Yes | QMessageBox.No
        )

        if install_reply != QMessageBox.Yes:
            QMessageBox.information(
                self,
                "Update Prepared",
                f"The update is ready in:\n{staged_path}\n\nYou can install it later from the staged package."
            )
            return

        install_success, install_message = self.update_manager.start_prepared_update()
        if not install_success:
            QMessageBox.warning(self, "Update Error", install_message)
            return

        QMessageBox.information(self, "Updating", install_message)
        QApplication.instance().quit()

    def _reset_runtime_views(self):
        """Prepare status widgets for a fresh scan."""
        self.table_results.setRowCount(0)
        self.text_raw.clear()
        self.text_insights.clear()
        self.text_report.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0%")
        self.label_elapsed.setText("Elapsed: 0.00s")

    def _render_results_table(self, results):
        """Render the final result set without duplicate in-flight rows."""
        self.table_results.setRowCount(0)
        for result in results:
            row = self.table_results.rowCount()
            self.table_results.insertRow(row)
            self.table_results.setItem(row, 0, QTableWidgetItem(str(result.port)))
            self.table_results.setItem(row, 1, QTableWidgetItem(result.service))
            self.table_results.setItem(row, 2, QTableWidgetItem(result.state))
            self.table_results.setItem(row, 3, QTableWidgetItem(result.version or '-'))
        self.current_results = list(results)

    def _update_elapsed_label(self):
        """Refresh elapsed time from the scanner manager clock."""
        if not self.scanner_manager.start_time:
            self.label_elapsed.setText("Elapsed: 0.00s")
            return

        elapsed = max(0.0, time.time() - self.scanner_manager.start_time)
        self.label_elapsed.setText(f"Elapsed: {elapsed:.2f}s")

    def _set_progress_style(self, chunk_color):
        """Update the progress-bar color based on scan state."""
        if chunk_color == self._current_progress_color:
            return

        self._current_progress_color = chunk_color
        self.progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: #8892A6;
                color: #1A1F2B;
                border: 1px solid #3A4358;
                border-radius: 3px;
                text-align: center;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
            }}
            """
        )
    
