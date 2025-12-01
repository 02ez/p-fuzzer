# LabLeakFinder - Installation & Setup Guide

## 🚀 Quick Start (5 Minutes)

### Step 1: Prerequisites Check
```bash
# Verify Python version (3.9+)
python --version

# Verify pip is available
pip --version
```

### Step 2: Clone Repository
```bash
git clone https://github.com/02ez/LabLeakFinder.git
cd LabLeakFinder
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Report Generator
```bash
python l6_report_generator.py
```

### Step 5: Open Report
```bash
# Windows
start final_penetration_test_report.html

# macOS
open final_penetration_test_report.html

# Linux
xdg-open final_penetration_test_report.html
```

---

## 📦 Installation Methods

### Method 1: Git Clone (Recommended)
```bash
# Clone repository
git clone https://github.com/02ez/LabLeakFinder.git
cd LabLeakFinder

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m pytest
```

### Method 2: Docker Container
```bash
# Build Docker image
docker build -t labfinder .

# Run container
docker run -v $(pwd)/reports:/app/reports labfinder

# Results in ./reports/
```

### Method 3: Python Virtual Environment (Best Practice)
```bash
# Create virtual environment
python -m venv labfinder_env

# Activate environment
# Windows:
labfinder_env\Scripts\activate
# macOS/Linux:
source labfinder_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

### Method 4: Conda Environment
```bash
# Create conda environment
conda create -n labfinder python=3.9

# Activate environment
conda activate labfinder

# Install dependencies
pip install -r requirements.txt
```

---

## 📋 System Requirements

### Minimum Requirements
- **OS**: Windows, macOS, or Linux
- **Python**: 3.9 or later
- **RAM**: 2GB minimum
- **Disk**: 100MB for installation + output
- **Network**: Internet (for updates only)

### Recommended Requirements
- **OS**: Ubuntu 20.04 LTS / Windows 11 / macOS 12+
- **Python**: 3.10 or later
- **RAM**: 4GB or more
- **Disk**: SSD with 500MB+ free space
- **CPU**: Multi-core processor

---

## 🔧 Configuration

### Default Configuration
Edit `l1_config_loader.py`:
```python
{
    "targets": ["target1.lab", "target2.lab"],
    "test_type": "black-box",
    "scope": "Active exploitation",
    "duration": "22 hours"
}
```

### Custom Configuration
1. Open `l1_config_loader.py`
2. Modify target list
3. Adjust test parameters
4. Save file
5. Run assessment

---

## 📂 Directory Structure

```
LabLeakFinder/
├── README.md                      ← Start here
├── FEATURES.md                    ← Feature overview
├── CONTRIBUTING.md                ← How to contribute
├── FAQ.md                         ← Frequently asked questions
├── requirements.txt               ← Python dependencies
├── l1_config_loader.py           ← Level 1: Configuration
├── l2_query_formatter.py         ← Level 2: Query formatting
├── l3_result_analyzer.py         ← Level 3: Result analysis
├── l4_exploit_validator.py       ← Level 4: Exploitation
├── l5_post_exploitation.py       ← Level 5: Post-exploitation
├── l6_report_generator.py        ← Level 6: Reporting
├── m1_connection_handler.py      ← Connection management
├── m2_m3_fuzzer.py              ← Fuzzing engine
├── reports/                       ← Generated reports directory
│   ├── final_penetration_test_report.html
│   ├── penetration_test_report.json
│   └── labfinder_l6_detailed.log
└── docs/                          ← Documentation
    ├── api.md
    ├── configuration.md
    └── troubleshooting.md
```

---

## 🚀 First Run Walkthrough

### Step 1: Verify Installation
```bash
# Check Python version
python --version
# Expected: Python 3.9+ 

# List installed packages
pip list | grep -E "pytest|requests"
```

### Step 2: Review Configuration
```bash
# Open configuration file
cat l1_config_loader.py

# Verify target scope matches your environment
# Update targets if needed
```

### Step 3: Run Report Generator
```bash
# Execute framework
python l6_report_generator.py

# Output:
# ================================================================================
# LabLeakFinder - L6 Final Penetration Test Report Generator
# ================================================================================
# ✓ HTML report exported to final_penetration_test_report.html
# ✓ JSON report exported to penetration_test_report.json
```

### Step 4: Review Generated Reports
```bash
# Open HTML report
open final_penetration_test_report.html

# View JSON data
cat penetration_test_report.json

# Check execution log
tail -50 labfinder_l6_detailed.log
```

---

## 🐛 Troubleshooting

### Issue: Python Version Error
```
Error: Python 3.9+ required
```
**Solution:**
```bash
# Install Python 3.9+
# Windows: Download from python.org
# macOS: brew install python@3.10
# Linux: apt-get install python3.10
```

### Issue: Missing Dependencies
```
ModuleNotFoundError: No module named 'requests'
```
**Solution:**
```bash
pip install -r requirements.txt --upgrade
```

### Issue: Permission Denied on Output
```
PermissionError: [Errno 13] Permission denied
```
**Solution:**
```bash
# Ensure write permissions
chmod 755 .
# Or run in different directory with proper permissions
```

### Issue: Report Generation Fails
```
KeyError or other exception
```
**Solution:**
1. Check `labfinder_l6_detailed.log` for error details
2. Verify configuration in `l1_config_loader.py`
3. Ensure all targets are accessible
4. Contact author with error log

---

## 🔄 Updating LabLeakFinder

### Update via Git
```bash
# Navigate to repository
cd LabLeakFinder

# Pull latest changes
git pull origin main

# Install updated dependencies
pip install -r requirements.txt --upgrade
```

### Update Dependencies Only
```bash
# Upgrade all packages
pip install -r requirements.txt --upgrade

# Or upgrade specific package
pip install --upgrade requests
```

---

## 🐳 Docker Setup (Alternative)

### Build Docker Image
```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "l6_report_generator.py"]
```

### Build and Run
```bash
# Build image
docker build -t labfinder:latest .

# Run container
docker run -v $(pwd)/reports:/app/reports labfinder:latest

# Run with custom config
docker run -v $(pwd)/config:/app/config \
           -v $(pwd)/reports:/app/reports \
           labfinder:latest
```

---

## ☁️ Cloud Deployment

### AWS Lambda
```bash
# Create deployment package
pip install -t package -r requirements.txt
cd package
zip -r ../labfinder.zip .
cd ..
zip -g labfinder.zip l*.py m*.py

# Upload to Lambda
aws lambda create-function \
  --function-name LabLeakFinder \
  --runtime python3.10 \
  --handler l6_report_generator.main \
  --zip-file fileb://labfinder.zip
```

### Azure Functions
```bash
# Create function app
func init LabLeakFinder --python

# Copy LabLeakFinder files
cp l*.py m*.py LabLeakFinder/

# Deploy
func azure functionapp publish <app-name>
```

---

## 🔐 Security Considerations

### Pre-Assessment Checklist
- ✅ Obtain written authorization
- ✅ Define scope clearly
- ✅ Document rules of engagement
- ✅ Ensure backup/recovery procedures
- ✅ Schedule during maintenance window
- ✅ Notify relevant teams

### During Assessment
- ✅ Monitor system performance
- ✅ Watch for unintended impacts
- ✅ Keep detailed logs
- ✅ Document all actions
- ✅ Have rollback procedures ready

### Post-Assessment
- ✅ Verify system stability
- ✅ Secure all reports
- ✅ Archive logs for compliance
- ✅ Share findings appropriately
- ✅ Plan remediation

---

## 📞 Getting Help

### Documentation
- **README.md**: Project overview
- **FEATURES.md**: Feature details
- **FAQ.md**: Frequently asked questions
- **CONTRIBUTING.md**: Developer guidelines
- **logs**: Check `labfinder_l6_detailed.log`

### Contact
- **Email**: [02ez@tostupidtooquit.com](mailto:02ez@tostupidtooquit.com)
- **Issues**: GitHub Issues for bugs/features
- **Discussions**: GitHub Discussions for questions

---

## ✅ Installation Verification Checklist

- [ ] Python 3.9+ installed
- [ ] Repository cloned
- [ ] Dependencies installed
- [ ] Configuration reviewed
- [ ] First report generated successfully
- [ ] HTML report opens in browser
- [ ] JSON export contains expected data
- [ ] Log file shows clean execution
- [ ] No error messages
- [ ] Ready for authorized testing!

---

## 🎓 Next Steps

1. **Read Documentation**
   - Review README.md for overview
   - Check FEATURES.md for capabilities
   - Read FAQ.md for answers

2. **Understand Configuration**
   - Edit l1_config_loader.py
   - Set your target scope
   - Customize test parameters

3. **Run First Assessment**
   - Execute l6_report_generator.py
   - Review generated reports
   - Analyze findings

4. **Interpret Results**
   - Understand CVSS scores
   - Review attack chains
   - Plan remediation

5. **Get Involved**
   - Report issues
   - Suggest features
   - Contribute code
   - Share knowledge

---

**Ready to get started? Run `python l6_report_generator.py` now!** 🚀

For detailed troubleshooting, check the logs:
```bash
tail -100 labfinder_l6_detailed.log
```
