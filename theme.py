stylesheet = """
QWidget {
    font-family: Arial, sans-serif;
    font-size: 12px;
    background-color: #ffffff;
    color: #373b41;
    padding: 4px;
}

QPushButton {
    background-color: #81a2be;
    color: #ffffff;
    border: none;
    padding: 4px 10px;
    border-radius: 6px;
    min-width: 100px;
}

QPushButton:hover {
    background-color: #5e7490;
}

QPushButton:pressed {
    background-color: #3e556e;
}

QLineEdit {
    background-color: #ffffff;
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 4px;
    color: #373b41;
}

QLineEdit:focus {
    border-color: #81a2be;
}

QRadioButton {
    font-size: 12px;
    padding: 2px 0;
    color: #373b41;
}

QGroupBox {
    font-size: 12px;
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 6px;
    color: #373b41;
}

QTableWidget {
    background-color: #ffffff;
    border: 1px solid #ccc;
    padding: 0px;
}

QTableWidget::item {
    padding: 2px;
}

QTableWidget QHeaderView {
    font-weight: bold;
    background-color: #f0f0f0;
    color: #373b41;
    padding: 0px;
}

QTableWidget QHeaderView::section {
    background-color: #f0f0f0;
    border: 1px solid #ccc;
    padding: 2px;
}

QListWidget {
    background-color: #ffffff;
    border-radius: 6px;
    border: 1px solid #ccc;
    padding: 4px;
}

QStatusBar {
    background-color: #f4f4f4;
    border: none;
    font-size: 12px;
    color: #373b41;
}

QLabel {
    font-size: 12px;
    color: #373b41;
}

QSplitter {
    border: 1px solid #ccc;
}

QSplitter::handle {
    background-color: #ccc;
    border-radius: 3px;
    width: 5px;
}

QPushButton:disabled {
    background-color: #969896;
    color: #c5c8c6;
}

QPushButton:enabled {
    background-color: #81a2be;
    color: #ffffff;
}

QPushButton:enabled:hover {
    background-color: #5e7490;
}

QPushButton:focus {
    outline: none;
}

QPushButton:disabled {
    background-color: #969896;
    color: #c5c8c6;
}

QPushButton:enabled {
    background-color: #81a2be;
    color: #ffffff;
}

QPushButton:enabled:hover {
    background-color: #5e7490;
}

"""
