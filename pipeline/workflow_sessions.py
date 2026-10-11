# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Protected, principal-owned, append-only interactive workflow sessions."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .approval_service import _canonical_bytes, _write_once
from .evidence_consumer import _decode_evidence

SCHEMA = 'formalspecgen-workflow-session-v1'
MAX_RECORD_BYTES = 1024 * 1024
MAX_REVISIONS = 128


class SessionError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class WorkflowSessionStore:
    """Each revision binds its predecessor; mutations require a revision match."""
    def __init__(self, root: Path, principal: str, *, now=time.time):
        if not principal.strip() or not root.is_absolute() or any(p.is_symlink() for p in (root,*root.parents)):
            raise SessionError('SESSION_CONFIGURATION_INVALID','protected root and principal required')
        if not root.is_dir() or root.stat().st_mode & 0o022:
            raise SessionError('SESSION_CONFIGURATION_INVALID','session root is writable by another principal')
        self.root,self.principal,self.now=root,principal,now

    def directory(self, session_id):
        if not isinstance(session_id,str) or not re.fullmatch('[0-9a-f]{32}',session_id):
            raise SessionError('SESSION_INVALID','invalid session identity')
        path=self.root/session_id
        if path.is_symlink():raise SessionError('SESSION_INVALID','symlinked session')
        return path

    @contextmanager
    def locked(self, session_id):
        directory=self.directory(session_id)
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            lock=os.open('.lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=descriptor)
            with os.fdopen(lock,'rb') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX)
                yield directory
        finally:os.close(descriptor)

    def load(self, session_id):
        directory=self.directory(session_id)
        versions=sorted(directory.glob('[0-9][0-9][0-9].json'))
        if not 1 <= len(versions) <= MAX_REVISIONS:
            raise SessionError('SESSION_INVALID','session history missing or exceeds limit')
        previous=None
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for revision,path in enumerate(versions):
                fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=descriptor)
                with os.fdopen(fd,'rb') as stream:raw=stream.read(MAX_RECORD_BYTES+1)
                if len(raw)>MAX_RECORD_BYTES:raise SessionError('SESSION_INVALID','session record exceeds limit')
                record=_decode_evidence(raw)
                if not isinstance(record,dict):raise SessionError('SESSION_INVALID','invalid session record')
                digest=record.pop('sha256',None)
                if (path.name!=f'{revision:03d}.json' or record.get('schema')!=SCHEMA or
                    record.get('session_id')!=session_id or record.get('revision')!=revision or
                    record.get('previous_sha256')!=previous or digest!=hashlib.sha256(_canonical_bytes(record)).hexdigest()):
                    raise SessionError('SESSION_INVALID','session history integrity failed')
                previous=digest;record['sha256']=digest
        finally:os.close(descriptor)
        if record['principal']!=self.principal:raise SessionError('SESSION_ACCESS_DENIED','session belongs to another principal')
        if self.now()>=record['expires_at']:raise SessionError('SESSION_EXPIRED','session expired')
        return record

    def append(self, record, changes):
        if set(changes) & {'schema','session_id','principal','kind','expires_at','workspace','output_root','revision','sha256','previous_sha256'}:
            raise SessionError('SESSION_INVALID','session identity cannot change')
        revision=record['revision']+1
        if revision>=MAX_REVISIONS:raise SessionError('SESSION_LIMIT_EXCEEDED','session revision limit reached')
        value={**record,**changes,'revision':revision,'previous_sha256':record['sha256']}
        value.pop('sha256',None)
        encoded=_canonical_bytes(value)
        if len(encoded)>MAX_RECORD_BYTES-100:raise SessionError('SESSION_LIMIT_EXCEEDED','session record exceeds limit')
        value['sha256']=hashlib.sha256(encoded).hexdigest()
        _write_once(self.directory(value['session_id'])/f'{revision:03d}.json',_canonical_bytes(value))
        return value

    def create(self, kind, payload):
        session_id=uuid.uuid4().hex
        self.directory(session_id).mkdir(mode=0o700)
        _write_once(self.directory(session_id)/'.lock',b'')
        record={**payload,'schema':SCHEMA,'session_id':session_id,'kind':kind,'principal':self.principal,
            'revision':-1,'sha256':None,'expires_at':self.now()+86400}
        return self.append(record,{})

    @staticmethod
    def require_revision(record, expected):
        if type(expected) is not int or expected!=record['revision']:
            raise SessionError('SESSION_REVISION_CONFLICT','inspect the current revision before changing this session')
