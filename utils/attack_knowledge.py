#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Index-backed MITRE ATT&CK helpers for attack-rule-auditor-v2.

This module intentionally reads compact index files rather than loading the full
enterprise-attack.json into an LLM context or Python memory for every query.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


class AttackKnowledge:
    def __init__(self, index_dir: str | Path = 'attack_data/index') -> None:
        self.index_dir = Path(index_dir)
        self._metadata: Optional[Dict[str, Any]] = None
        self._lookup: Optional[Dict[str, Dict[str, Any]]] = None

    @property
    def metadata(self) -> Dict[str, Any]:
        if self._metadata is None:
            path = self.index_dir / 'metadata.json'
            self._metadata = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        return self._metadata

    @property
    def lookup(self) -> Dict[str, Dict[str, Any]]:
        if self._lookup is None:
            path = self.index_dir / 'lookup_by_id.json'
            self._lookup = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        return self._lookup

    def get(self, attack_id: str) -> Optional[Dict[str, Any]]:
        return self.lookup.get(attack_id)

    def validate_id(self, attack_id: str) -> bool:
        return attack_id in self.lookup

    def children_of(self, parent_id: str) -> List[Dict[str, Any]]:
        prefix = f'{parent_id}.'
        return [row for tid, row in self.lookup.items() if tid.startswith(prefix)]

    def parent_of(self, attack_id: str) -> Optional[Dict[str, Any]]:
        row = self.get(attack_id)
        if not row:
            return None
        parent_id = row.get('parent_id')
        return self.get(parent_id) if parent_id else None

    def load_jsonl(self, path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        with path.open('r', encoding='utf-8') as f:
            return [json.loads(line) for line in f if line.strip()]

    def rows_for_platform(self, platform: str) -> List[Dict[str, Any]]:
        safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', platform)
        return self.load_jsonl(self.index_dir / 'by_platform' / f'{safe}.jsonl')

    def rows_for_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', tactic)
        return self.load_jsonl(self.index_dir / 'by_tactic' / f'{safe}.jsonl')

    def linux_container_scope(self) -> List[Dict[str, Any]]:
        return self.load_jsonl(self.index_dir / 'linux_container_scope.jsonl')

    @staticmethod
    def _score(row: Dict[str, Any], keywords: Sequence[str]) -> int:
        text = ' '.join([
            row.get('technique_id', ''),
            row.get('name', ''),
            row.get('description', ''),
            ' '.join(row.get('tactics', [])),
            ' '.join(row.get('platforms', [])),
            ' '.join(row.get('data_components', [])),
        ]).lower()
        score = 0
        for kw in keywords:
            kw = kw.lower().strip()
            if not kw or len(kw) < 3:
                continue
            if kw in row.get('name', '').lower():
                score += 5
            if kw in text:
                score += 1
        return score

    def query(self, *, platforms: Sequence[str] = (), tactics: Sequence[str] = (), keywords: Sequence[str] = (), limit: int = 50) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if platforms:
            seen: Set[str] = set()
            for p in platforms:
                for row in self.rows_for_platform(p):
                    if row['technique_id'] not in seen:
                        seen.add(row['technique_id'])
                        rows.append(row)
        else:
            rows = self.linux_container_scope()

        if tactics:
            tactic_set = {t.lower() for t in tactics}
            rows = [r for r in rows if tactic_set.intersection({t.lower() for t in r.get('tactics', [])})]

        if keywords:
            scored = [(self._score(r, keywords), r) for r in rows]
            rows = [r for score, r in sorted(scored, key=lambda x: x[0], reverse=True) if score > 0]

        return rows[:limit]

    def scenario_seed_candidates(self, scenario_key: str) -> List[Dict[str, Any]]:
        path = self.index_dir.parent / 'models' / 'scenario_seed_map.json'
        if not path.exists():
            path = self.index_dir / 'scenario_seed_map.json'
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding='utf-8'))
        ids = data.get(scenario_key, {}).get('candidate_ids', [])
        return [self.lookup[i] for i in ids if i in self.lookup]

    def build_denominator(self, *, scenario_key: Optional[str] = None, platforms: Sequence[str] = ('Linux', 'Containers'), tactics: Sequence[str] = (), keywords: Sequence[str] = (), include_children: bool = True, limit: int = 200) -> List[Dict[str, Any]]:
        candidates: Dict[str, Dict[str, Any]] = {}

        if scenario_key:
            for row in self.scenario_seed_candidates(scenario_key):
                candidates[row['technique_id']] = row

        for row in self.query(platforms=platforms, tactics=tactics, keywords=keywords, limit=limit):
            candidates[row['technique_id']] = row

        if include_children:
            for tid in list(candidates.keys()):
                for child in self.children_of(tid):
                    if any(p in child.get('platforms', []) for p in platforms):
                        candidates[child['technique_id']] = child

        return sorted(candidates.values(), key=lambda r: r['technique_id'])

    def verify_declared_mapping(self, declared_ids: Sequence[str], *, behavior_keywords: Sequence[str], platforms: Sequence[str]) -> Dict[str, Any]:
        result = {
            'valid': [],
            'invalid': [],
            'platform_mismatch': [],
            'parent_only': [],
            'low_semantic_match': [],
        }
        platform_set = set(platforms)
        for tid in declared_ids:
            row = self.get(tid)
            if not row:
                result['invalid'].append({'id': tid, 'reason': 'ATT&CK ID not found in index'})
                continue
            if platform_set and not platform_set.intersection(row.get('platforms', [])):
                result['platform_mismatch'].append({'id': tid, 'name': row.get('name'), 'platforms': row.get('platforms', [])})
            if not row.get('is_subtechnique') and self.children_of(tid):
                result['parent_only'].append({'id': tid, 'name': row.get('name'), 'children': [c['technique_id'] for c in self.children_of(tid)]})
            if behavior_keywords and self._score(row, behavior_keywords) == 0:
                result['low_semantic_match'].append({'id': tid, 'name': row.get('name')})
            result['valid'].append({'id': tid, 'name': row.get('name')})
        return result
