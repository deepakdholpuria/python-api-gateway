from setuptools import setup, find_packages

setup(
    name="gateway_router",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "oracledb>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "gateway_router=gateway_router:main",
        ],
    },
    python_requires=">=3.6",
    author="Your Name",
    author_email="your.email@example.com",
    description="A Python-based gateway routing application",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/gateway-router",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)