# ============================================================================
# FILE 3: pentoolkit/utils/deduplication.py - Finding Deduplication
# ============================================================================

import difflib
import hashlib
from typing import List, Dict, Any


class FindingDeduplicator:
    """
    Deduplicate and merge findings from multiple tools.
    
    Features:
        - Exact title/description matching
        - Fuzzy matching for similar findings
        - Merge findings from different tools
        - Severity elevation
    """
    
    def __init__(self, fuzzy_threshold: float = 0.8):
        """
        Initialize deduplicator.
        
        Args:
            fuzzy_threshold: Threshold for fuzzy matching (0-1)
        """
        self.fuzzy_threshold = fuzzy_threshold
        self.seen_hashes = set()
    
    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings using multiple strategies.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Deduplicated list with merged findings
        """
        if not findings:
            return []
        
        # Strategy 1: Exact matching (title + description)
        unique_exact = self._exact_deduplicate(findings)
        
        # Strategy 2: Fuzzy matching (similar findings)
        merged = self._fuzzy_merge(unique_exact)
        
        # Strategy 3: Elevation (upgrade severity if found in multiple tools)
        elevated = self._elevate_severity(merged)
        
        return elevated
    
    def _exact_deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove exact duplicates."""
        seen = {}
        unique = []
        
        for finding in findings:
            # Create fingerprint
            fp = self._create_fingerprint(
                finding.get('title', ''),
                finding.get('description', '')
            )
            
            if fp not in seen:
                seen[fp] = finding
                unique.append(finding)
            else:
                # Keep highest severity
                if self._severity_rank(finding.get('severity')) > \
                   self._severity_rank(seen[fp].get('severity')):
                    idx = unique.index(seen[fp])
                    unique[idx] = finding
                    seen[fp] = finding
        
        return unique
    
    def _fuzzy_merge(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge similar findings (fuzzy matching)."""
        merged = []
        used_indices = set()
        
        for i, finding1 in enumerate(findings):
            if i in used_indices:
                continue
            
            similar_findings = [finding1]
            
            for j, finding2 in enumerate(findings[i+1:], start=i+1):
                if j in used_indices:
                    continue
                
                similarity = self._similarity_ratio(
                    finding1.get('title', ''),
                    finding2.get('title', '')
                )
                
                if similarity >= self.fuzzy_threshold:
                    similar_findings.append(finding2)
                    used_indices.add(j)
            
            # Merge similar findings
            merged_finding = self._merge_findings(similar_findings)
            merged.append(merged_finding)
            used_indices.add(i)
        
        return merged
    
    def _merge_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple similar findings into one."""
        if len(findings) == 1:
            return findings[0]
        
        # Use first finding as base
        merged = findings[0].copy()
        
        # Combine evidence from all findings
        all_evidence = []
        all_tools = []
        highest_severity = merged.get('severity', 'info')
        
        for finding in findings:
            evidence = finding.get('evidence', '')
            if evidence:
                tool = finding.get('tool', 'unknown')
                all_evidence.append(f"[{tool}] {evidence}")
                all_tools.append(tool)
            
            # Elevate severity
            if self._severity_rank(finding.get('severity')) > \
               self._severity_rank(highest_severity):
                highest_severity = finding.get('severity')
        
        # Update merged finding
        merged['evidence'] = "\n\n".join(all_evidence)
        merged['severity'] = highest_severity
        merged['tools'] = list(set(all_tools))
        merged['merged_from'] = len(findings)
        
        return merged
    
    def _elevate_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Elevate severity if finding appears critical in multiple sources."""
        for finding in findings:
            # If finding was merged from multiple tools, elevate severity
            if finding.get('merged_from', 1) > 1:
                current = finding.get('severity', 'info')
                
                # Upgrade: info -> low, low -> medium, etc.
                severity_levels = ['info', 'low', 'medium', 'high', 'critical']
                if current in severity_levels:
                    idx = severity_levels.index(current)
                    if idx < len(severity_levels) - 1:
                        finding['severity'] = severity_levels[idx + 1]
        
        return findings
    
    def _create_fingerprint(self, title: str, description: str) -> str:
        """Create SHA256 fingerprint of finding."""
        content = f"{title.lower().strip()}:{description.lower().strip()}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _similarity_ratio(self, str1: str, str2: str) -> float:
        """Calculate similarity ratio between two strings (0-1)."""
        return difflib.SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def _severity_rank(self, severity: str) -> int:
        """Get numeric rank for severity level."""
        ranks = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return ranks.get(severity.lower(), 0)