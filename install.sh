#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

# Function to print warning messages
print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root or with sudo"
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        print_success "Detected OS: $OS"
    else
        print_error "Could not detect OS"
    fi
}

# Install system dependencies based on OS
install_system_deps() {
    echo "Installing system dependencies..."
    
    case $OS in
        "Ubuntu"|"Debian GNU/Linux")
            apt-get update
            apt-get install -y python3 python3-pip python3-tk libusb-1.0-0-dev
            ;;
        "Fedora")
            dnf install -y python3 python3-pip python3-tkinter libusb-devel
            ;;
        "Arch Linux")
            pacman -Sy --noconfirm python python-pip tk libusb
            ;;
        *)
            print_warning "Unsupported OS. Please install these packages manually:"
            echo "- Python 3"
            echo "- Python 3 pip"
            echo "- Python 3 tkinter"
            echo "- libusb development package"
            ;;
    esac
}

# Setup Python virtual environment
setup_venv() {
    echo "Setting up Python virtual environment..."
    
    # Install venv if not already installed
    case $OS in
        "Ubuntu"|"Debian GNU/Linux")
            apt-get install -y python3-venv
            ;;
        "Fedora")
            dnf install -y python3-virtualenv
            ;;
        "Arch Linux")
            pacman -Sy --noconfirm python-virtualenv
            ;;
    esac
    
    # Create and activate virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    print_success "Virtual environment created and activated"
}

# Install Python dependencies
install_python_deps() {
    echo "Installing Python dependencies..."
    
    # Create requirements.txt if it doesn't exist
    if [ ! -f requirements.txt ]; then
        echo "pyusb>=1.2.1" > requirements.txt
        echo "tk>=0.1.0" >> requirements.txt
        echo "pathlib>=1.0.1" >> requirements.txt
    fi
    
    # Upgrade pip
    pip3 install --upgrade pip
    
    # Install requirements
    pip3 install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Configure USB permissions
setup_usb_permissions() {
    echo "Setting up USB permissions..."
    
    # Create udev rules
    RULES_FILE="/etc/udev/rules.d/99-usb.rules"
    
    # Backup existing rules if they exist
    if [ -f "$RULES_FILE" ]; then
        mv "$RULES_FILE" "$RULES_FILE.backup"
        print_warning "Existing USB rules backed up to $RULES_FILE.backup"
    fi
    
    # Create new rules
    echo 'SUBSYSTEM=="usb", MODE="0666"' > "$RULES_FILE"
    
    # Create plugdev group if it doesn't exist
    getent group plugdev || groupadd plugdev
    
    # Add current user to plugdev group
    SUDO_USER=$(logname)
    usermod -a -G plugdev "$SUDO_USER"
    
    # Reload udev rules
    udevadm control --reload-rules
    udevadm trigger
    
    print_success "USB permissions configured"
    print_warning "Please log out and log back in for group changes to take effect"
}

# Main installation process
main() {
    echo "Starting USB Management Tool Installation"
    echo "----------------------------------------"
    
    # Check if running as root
    check_root
    
    # Detect operating system
    detect_os
    
    # Install system dependencies
    install_system_deps
    
    # Setup Python virtual environment
    setup_venv
    
    # Install Python dependencies
    install_python_deps
    
    # Setup USB permissions
    setup_usb_permissions
    
    echo "----------------------------------------"
    print_success "Installation completed successfully!"
    echo "To use the tool:"
    echo "1. Log out and log back in for USB permissions to take effect"
    echo "2. Activate the virtual environment: source venv/bin/activate"
    echo "3. Run the tool: python3 data_scraper.py"
}

# Run main installation
main
