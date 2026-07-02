from setuptools import setup, find_packages

setup(
    name="phishing-email-analyzer",
    version="1.0.0",
    description="A rule-based heuristics & risk scoring engine for phishing detection",
    author="SOC Team",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "PyYAML>=6.0",
        "reportlab>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "phishing-analyzer=phishing_analyzer.main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
