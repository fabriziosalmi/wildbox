import re
import time
import aiohttp
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

try:
    from .schemas import (
        BlockchainSecurityAnalyzerInput, 
        BlockchainSecurityAnalyzerOutput, 
        SecurityVulnerability, 
        GasOptimization
    )
except ImportError:
    from schemas import (
        BlockchainSecurityAnalyzerInput, 
        BlockchainSecurityAnalyzerOutput, 
        SecurityVulnerability, 
        GasOptimization
    )

# Tool metadata
TOOL_INFO = {
    "name": "Blockchain Security Analyzer",
    "description": "Comprehensive smart contract security analysis tool for detecting vulnerabilities, gas optimization opportunities, and security best practices violations",
    "category": "cryptography",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["blockchain", "smart-contracts", "solidity", "ethereum", "defi", "security"]
}

async def execute_tool(data: BlockchainSecurityAnalyzerInput) -> BlockchainSecurityAnalyzerOutput:
    """
    Analyze smart contract for security vulnerabilities and optimizations
    """
    start_time = time.time()
    vulnerabilities = []
    gas_optimizations = []
    recommendations = []
    
    contract_code = data.contract_code
    contract_verified = None
    contract_balance = None
    proxy_contract = None
    
    # If contract address provided, try to fetch contract details
    if data.contract_address and not contract_code:
        contract_info = await fetch_contract_info(data.contract_address, data.blockchain, data.api_key)
        if contract_info:
            contract_code = contract_info.get('source_code', '')
            contract_verified = contract_info.get('verified', False)
            contract_balance = contract_info.get('balance')
            proxy_contract = contract_info.get('is_proxy', False)
    
    if not contract_code:
        vulnerabilities.append(SecurityVulnerability(
            severity="Info",
            category="Analysis",
            title="No Contract Code Available",
            description="Unable to analyze contract - no source code provided or found",
            recommendation="Provide contract source code or ensure contract is verified on blockchain explorer"
        ))
    else:
        # Perform comprehensive security analysis
        if data.check_reentrancy:
            await check_reentrancy_vulnerabilities(contract_code, vulnerabilities)
        
        if data.check_overflow:
            await check_overflow_vulnerabilities(contract_code, vulnerabilities)
        
        if data.check_access_control:
            await check_access_control_issues(contract_code, vulnerabilities)
        
        if data.check_gas_optimization:
            await check_gas_optimizations(contract_code, gas_optimizations)
        
        # Additional security checks
        await check_external_calls(contract_code, vulnerabilities)
        await check_randomness_issues(contract_code, vulnerabilities)
        await check_timestamp_dependencies(contract_code, vulnerabilities)
        await check_tx_origin_usage(contract_code, vulnerabilities)
        await check_delegatecall_usage(contract_code, vulnerabilities)
        await check_unchecked_low_level_calls(contract_code, vulnerabilities)
        await check_flash_loan_vulnerabilities(contract_code, vulnerabilities)
        await check_front_running_vulnerabilities(contract_code, vulnerabilities)
    
    # Generate recommendations based on findings
    recommendations = generate_recommendations(vulnerabilities, gas_optimizations)
    
    # Calculate security metrics
    total_vulns = len(vulnerabilities)
    critical_vulns = len([v for v in vulnerabilities if v.severity == "Critical"])
    high_vulns = len([v for v in vulnerabilities if v.severity == "High"])
    medium_vulns = len([v for v in vulnerabilities if v.severity == "Medium"])
    low_vulns = len([v for v in vulnerabilities if v.severity == "Low"])
    
    security_score = calculate_security_score(vulnerabilities)
    risk_level = determine_risk_level(critical_vulns, high_vulns, medium_vulns)
    
    return BlockchainSecurityAnalyzerOutput(
        contract_address=data.contract_address,
        blockchain=data.blockchain,
        analysis_timestamp=datetime.utcnow().isoformat(),
        total_vulnerabilities=total_vulns,
        critical_vulnerabilities=critical_vulns,
        high_vulnerabilities=high_vulns,
        medium_vulnerabilities=medium_vulns,
        low_vulnerabilities=low_vulns,
        vulnerabilities=vulnerabilities,
        gas_optimizations=gas_optimizations,
        contract_balance=contract_balance,
        contract_verified=contract_verified,
        proxy_contract=proxy_contract,
        security_score=security_score,
        risk_level=risk_level,
        recommendations=recommendations,
        execution_time=time.time() - start_time
    )

async def fetch_contract_info(address: str, blockchain: str, api_key: Optional[str]) -> Optional[Dict]:
    """Fetch contract information from blockchain explorer"""
    try:
        if not api_key:
            return None
            
        # Ethereum/BSC using Etherscan API
        if blockchain.lower() in ['ethereum', 'eth', 'bsc', 'binance']:
            return await fetch_etherscan_contract_info(address, blockchain, api_key)
        
        # Polygon using PolygonScan API
        elif blockchain.lower() in ['polygon', 'matic']:
            return await fetch_polygonscan_contract_info(address, api_key)
        
        # Add more blockchain integrations as needed
        else:
            return None
            
    except Exception as e:
        print(f"Error fetching contract info: {e}")
        return None

async def fetch_etherscan_contract_info(address: str, blockchain: str, api_key: str) -> Optional[Dict]:
    """Fetch contract info from Etherscan-compatible APIs"""
    base_urls = {
        'ethereum': 'https://api.etherscan.io/api',
        'bsc': 'https://api.bscscan.com/api'
    }
    
    base_url = base_urls.get(blockchain.lower(), 'https://api.etherscan.io/api')
    
    async with aiohttp.ClientSession() as session:
        # Get contract source code
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': api_key
        }
        
        async with session.get(base_url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                if data['status'] == '1' and data['result']:
                    contract_data = data['result'][0]
                    
                    # Get contract balance
                    balance_params = {
                        'module': 'account',
                        'action': 'balance',
                        'address': address,
                        'tag': 'latest',
                        'apikey': api_key
                    }
                    
                    balance = '0 ETH'
                    try:
                        async with session.get(base_url, params=balance_params) as balance_response:
                            if balance_response.status == 200:
                                balance_data = await balance_response.json()
                                if balance_data['status'] == '1':
                                    wei_balance = int(balance_data['result'])
                                    eth_balance = wei_balance / 10**18
                                    balance = f"{eth_balance:.6f} ETH"
                    except:
                        pass
                    
                    return {
                        'source_code': contract_data.get('SourceCode', ''),
                        'verified': contract_data.get('SourceCode', '') != '',
                        'balance': balance,
                        'is_proxy': contract_data.get('Proxy', '0') == '1',
                        'contract_name': contract_data.get('ContractName', ''),
                        'compiler_version': contract_data.get('CompilerVersion', '')
                    }
    
    return None

async def fetch_polygonscan_contract_info(address: str, api_key: str) -> Optional[Dict]:
    """Fetch contract info from PolygonScan API"""
    base_url = 'https://api.polygonscan.com/api'
    
    async with aiohttp.ClientSession() as session:
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': api_key
        }
        
        async with session.get(base_url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                if data['status'] == '1' and data['result']:
                    contract_data = data['result'][0]
                    
                    # Get MATIC balance
                    balance_params = {
                        'module': 'account',
                        'action': 'balance',
                        'address': address,
                        'tag': 'latest',
                        'apikey': api_key
                    }
                    
                    balance = '0 MATIC'
                    try:
                        async with session.get(base_url, params=balance_params) as balance_response:
                            if balance_response.status == 200:
                                balance_data = await balance_response.json()
                                if balance_data['status'] == '1':
                                    wei_balance = int(balance_data['result'])
                                    matic_balance = wei_balance / 10**18
                                    balance = f"{matic_balance:.6f} MATIC"
                    except:
                        pass
                    
                    return {
                        'source_code': contract_data.get('SourceCode', ''),
                        'verified': contract_data.get('SourceCode', '') != '',
                        'balance': balance,
                        'is_proxy': contract_data.get('Proxy', '0') == '1',
                        'contract_name': contract_data.get('ContractName', ''),
                        'compiler_version': contract_data.get('CompilerVersion', '')
                    }
    
    return None

async def check_reentrancy_vulnerabilities(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for reentrancy vulnerabilities"""
    # Pattern for external calls before state changes
    external_call_patterns = [
        r'\.call\s*\(',
        r'\.send\s*\(',
        r'\.transfer\s*\(',
        r'\.delegatecall\s*\(',
        r'external\s+.*\s*\('
    ]
    
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        for pattern in external_call_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if state changes occur after external call
                remaining_lines = lines[i:]
                if any(re.search(r'(\w+)\s*=', remaining_line) for remaining_line in remaining_lines[:10]):
                    vulnerabilities.append(SecurityVulnerability(
                        severity="High",
                        category="Reentrancy",
                        title="Potential Reentrancy Vulnerability",
                        description="External call detected before state changes, potentially vulnerable to reentrancy attacks",
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use the checks-effects-interactions pattern: check conditions, make state changes, then interact with external contracts",
                        cwe_id="CWE-841"
                    ))

async def check_overflow_vulnerabilities(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for integer overflow/underflow vulnerabilities"""
    # Check for arithmetic operations without SafeMath (pre-Solidity 0.8.0)
    if 'pragma solidity' in code:
        version_match = re.search(r'pragma solidity\s*[\^>=<]*(\d+\.\d+)', code)
        if version_match:
            version = float(version_match.group(1))
            if version < 0.8:
                arithmetic_patterns = [r'\+\s*\w+', r'-\s*\w+', r'\*\s*\w+', r'/\s*\w+']
                lines = code.split('\n')
                for i, line in enumerate(lines, 1):
                    for pattern in arithmetic_patterns:
                        if re.search(pattern, line) and 'SafeMath' not in line:
                            vulnerabilities.append(SecurityVulnerability(
                                severity="Medium",
                                category="Arithmetic",
                                title="Potential Integer Overflow/Underflow",
                                description="Arithmetic operation without overflow protection detected",
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow protection",
                                cwe_id="CWE-190"
                            ))

async def check_access_control_issues(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for access control vulnerabilities"""
    # Check for functions without proper access modifiers
    function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\s*\{'
    
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        match = re.search(function_pattern, line)
        if match:
            func_name = match.group(1)
            modifiers = match.group(2)
            
            # Check for missing access modifiers on critical functions
            critical_functions = ['withdraw', 'transfer', 'mint', 'burn', 'selfdestruct', 'kill']
            if any(keyword in func_name.lower() for keyword in critical_functions):
                if not any(modifier in modifiers for modifier in ['onlyOwner', 'onlyAdmin', 'private', 'internal']):
                    vulnerabilities.append(SecurityVulnerability(
                        severity="High",
                        category="Access Control",
                        title="Missing Access Control",
                        description=f"Critical function '{func_name}' lacks proper access control",
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Add appropriate access control modifiers (onlyOwner, onlyAdmin, etc.)",
                        cwe_id="CWE-284"
                    ))

async def check_gas_optimizations(code: str, optimizations: List[GasOptimization]):
    """Check for gas optimization opportunities"""
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Check for storage vs memory usage
        if re.search(r'string\s+storage', line):
            optimizations.append(GasOptimization(
                title="Use Memory Instead of Storage",
                description="Consider using memory instead of storage for temporary string variables",
                potential_savings="High",
                line_number=i,
                recommendation="Use 'memory' keyword for temporary variables to reduce gas costs"
            ))
        
        # Check for unnecessary storage reads
        if line.count('.') > 2 and 'storage' in line:
            optimizations.append(GasOptimization(
                title="Cache Storage Reads",
                description="Multiple storage reads detected - consider caching in memory",
                potential_savings="Medium",
                line_number=i,
                recommendation="Cache frequently accessed storage variables in memory"
            ))

async def check_external_calls(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for unsafe external calls"""
    if re.search(r'\.call\s*\(', code):
        vulnerabilities.append(SecurityVulnerability(
            severity="Medium",
            category="External Calls",
            title="Low-level Call Detected",
            description="Low-level call() detected - ensure proper error handling",
            recommendation="Use specific function calls instead of call() where possible, and always check return values"
        ))

async def check_randomness_issues(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for weak randomness sources"""
    weak_random_patterns = [
        r'block\.timestamp',
        r'block\.number',
        r'block\.difficulty',
        r'blockhash\s*\('
    ]
    
    for pattern in weak_random_patterns:
        if re.search(pattern, code):
            vulnerabilities.append(SecurityVulnerability(
                severity="Medium",
                category="Randomness",
                title="Weak Randomness Source",
                description="Using blockchain properties for randomness can be manipulated by miners",
                recommendation="Use oracle-based randomness (Chainlink VRF) or commit-reveal schemes",
                cwe_id="CWE-338"
            ))

async def check_timestamp_dependencies(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for timestamp dependence vulnerabilities"""
    if re.search(r'block\.timestamp', code) or re.search(r'now\s', code):
        vulnerabilities.append(SecurityVulnerability(
            severity="Low",
            category="Timestamp Dependence",
            title="Timestamp Dependence",
            description="Contract behavior depends on block timestamp which can be manipulated",
            recommendation="Avoid critical logic based on exact timestamps, use block numbers or longer time periods"
        ))

async def check_tx_origin_usage(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for tx.origin usage"""
    if re.search(r'tx\.origin', code):
        vulnerabilities.append(SecurityVulnerability(
            severity="High",
            category="Authentication",
            title="tx.origin Usage",
            description="Using tx.origin for authentication is vulnerable to phishing attacks",
            recommendation="Use msg.sender instead of tx.origin for authentication",
            cwe_id="CWE-283"
        ))

async def check_delegatecall_usage(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for unsafe delegatecall usage"""
    if re.search(r'\.delegatecall\s*\(', code):
        vulnerabilities.append(SecurityVulnerability(
            severity="High",
            category="Delegatecall",
            title="Unsafe Delegatecall",
            description="Delegatecall allows arbitrary code execution - ensure target contract is trusted",
            recommendation="Validate target contract and consider using staticcall where possible"
        ))

async def check_unchecked_low_level_calls(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for unchecked return values from low-level calls"""
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        if re.search(r'\.call\s*\(', line) or re.search(r'\.send\s*\(', line):
            # Check if return value is checked
            if not re.search(r'(bool|require|assert)', line) and not re.search(r'(bool|require|assert)', lines[min(i, len(lines)-1)]):
                vulnerabilities.append(SecurityVulnerability(
                    severity="Medium",
                    category="Return Values",
                    title="Unchecked Call Return Value",
                    description="Low-level call return value not checked",
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Always check return values from external calls using require() or if statements"
                ))

async def check_flash_loan_vulnerabilities(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for flash loan attack vulnerabilities"""
    flash_loan_indicators = ['flashloan', 'flash_loan', 'borrow', 'flashBorrow']
    
    if any(indicator in code.lower() for indicator in flash_loan_indicators):
        if 'reentrancyGuard' not in code and 'nonReentrant' not in code:
            vulnerabilities.append(SecurityVulnerability(
                severity="High",
                category="Flash Loan",
                title="Potential Flash Loan Vulnerability",
                description="Flash loan functionality detected without proper reentrancy protection",
                recommendation="Implement reentrancy guards and state validation for flash loan functions"
            ))

async def check_front_running_vulnerabilities(code: str, vulnerabilities: List[SecurityVulnerability]):
    """Check for front-running vulnerabilities"""
    # Check for price-dependent operations without protection
    if re.search(r'price\s*\*', code) or re.search(r'getPrice\s*\(', code):
        if 'commit' not in code.lower() and 'reveal' not in code.lower():
            vulnerabilities.append(SecurityVulnerability(
                severity="Medium",
                category="MEV",
                title="Front-running Vulnerability",
                description="Price-dependent operations may be vulnerable to front-running attacks",
                recommendation="Implement commit-reveal schemes or use MEV protection mechanisms"
            ))

def generate_recommendations(vulnerabilities: List[SecurityVulnerability], optimizations: List[GasOptimization]) -> List[str]:
    """Generate actionable recommendations based on findings"""
    recommendations = []
    
    if vulnerabilities:
        recommendations.append("Address all identified security vulnerabilities before deployment")
        
        critical_high = [v for v in vulnerabilities if v.severity in ["Critical", "High"]]
        if critical_high:
            recommendations.append("Prioritize fixing Critical and High severity vulnerabilities immediately")
    
    if optimizations:
        recommendations.append("Implement gas optimizations to reduce transaction costs")
    
    recommendations.extend([
        "Conduct thorough testing including unit tests and integration tests",
        "Consider formal verification for critical contracts",
        "Implement proper access controls and multi-signature requirements",
        "Set up monitoring and alerting for unusual contract activity",
        "Consider bug bounty programs before mainnet deployment"
    ])
    
    return recommendations

def calculate_security_score(vulnerabilities: List[SecurityVulnerability]) -> float:
    """Calculate security score based on vulnerabilities"""
    if not vulnerabilities:
        return 100.0
    
    score = 100.0
    severity_weights = {
        "Critical": 40,
        "High": 25,
        "Medium": 10,
        "Low": 5,
        "Info": 1
    }
    
    for vuln in vulnerabilities:
        score -= severity_weights.get(vuln.severity, 1)
    
    return max(0.0, score)

def determine_risk_level(critical: int, high: int, medium: int) -> str:
    """Determine overall risk level"""
    if critical > 0:
        return "Critical"
    elif high > 2:
        return "High"
    elif high > 0 or medium > 5:
        return "Medium"
    else:
        return "Low"

# Export tool info for registration
tool_info = TOOL_INFO
