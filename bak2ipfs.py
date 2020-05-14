#!/usr/bin/env python3

import os
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime
import regex as re
import shutil
import json
import base64
import hashlib
import ipfshttpclient
import argparse
import getpass
from Crypto import Random
from Crypto.Cipher import AES


DEFAULT_MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1Gb


ChunksFileInfo = Dict[
    str,
    Any
]


class Backup2ipfs():
    def __init__(self,
                 password: str,
                 root_dir: str = "",
                 ipfs_addrs: str = "",
                 index_file: str = ".ipfs.index",
                 index_key_id_file: str = ".ipfs.index.key_id",
                 published_name_file: str = ".ipfs.published",
                 local_key_name: str = "local-backup",
                 max_file_size: int = DEFAULT_MAX_FILE_SIZE,
                 ignore: List[str] = []) -> None:
        self._root_dir = root_dir if root_dir else "."
        self._local_key_name = local_key_name
        self._max_file_size = max_file_size

        self._ipfs_defaults = {
            "stream": False,
            "offline": False,
            "timeout": 5 * 60
        }

        ignore_files = [
            os.path.basename(index_file) + "*",
            os.path.basename(index_key_id_file) + "*",
            os.path.basename(published_name_file) + "*"
        ]

        self._ignore_file_regexs = [
            re.compile(file_regex) for file_regex in ignore_files
        ]

        self._ignore_file_regexs += [
            re.compile(ignore_regex) for ignore_regex in ignore
        ]

        self._index_file = os.path.join(
            root_dir,
            index_file
        )

        self._index_key_id_file = os.path.join(
            root_dir,
            index_key_id_file
        )

        self._published_name_file = os.path.join(
            root_dir,
            published_name_file
        )

        self._password = password
        self._crypto = AESCipher(password)

        self._ipfs_client = ipfshttpclient.connect(
            ipfs_addrs,
            **self._ipfs_defaults
        )
        self._setup_key()

    def _setup_key(self):
        keys = self._ipfs_client.key.list(**self._ipfs_defaults)
        keys_name = [ value["Name"] for value in keys["Keys"] ]
        if self._local_key_name in keys_name:
            return
        self._ipfs_client.key.gen(
            self._local_key_name,
            "rsa",
            **self._ipfs_defaults
        )

    def _transverse_directories(self) -> Dict[str, Dict[str, Any]]:
        file_index = dict()
        for root, _, files in os.walk(self._root_dir):
            for file_name in files:
                relative_path = os.path.join(root, file_name)
                absolute_path = os.path.abspath(relative_path)
                if self._ignore_file(absolute_path):
                    continue
                try:
                    file_info = self._process_file(absolute_path)
                    if file_info is None:
                        continue
                    self._store_file_on_network(file_info)
                    file_index[relative_path[2:]] = file_info
                except (MaxFileSizeException, NotIsFileException):
                    continue
        return file_index
    
    def _process_file(self, absolute_path: str):
        file_chunks = FileChunks()
        file_info = file_chunks.create(absolute_path, self._password)
        return file_info

    def _store_file_on_network(self, file_info: ChunksFileInfo):
        for chunk in file_info["chunks"]:
            data = chunk["data"]
            del chunk["data"]
            chunk["key_id"] = self._ipfs_client.add_bytes(data, **self._ipfs_defaults)

    def backup(self):
        file_index = self._transverse_directories()
        self._pin_files(file_index)
        self._check_if_files_are_pinned(file_index)
        # Save index for future restore of the data.
        self._store_index_locally(file_index)
        # Store index on network too.
        index_key_id = self._store_index_on_network(file_index)
        self._save_key_id(index_key_id, self._index_key_id_file)
        published_name = self._publish_index(index_key_id)
        self._save_key_id(published_name, self._published_name_file)

    def _publish_index(self, index_key_id: str):
        published = self._ipfs_client.name.publish(
            index_key_id,
            lifetime = f"24h",
            allow_offline = True,
            key = self._local_key_name,
            **self._ipfs_defaults
        )
        return published["Name"]

    def _pin_files(self, file_index: Dict[str, Dict[str, Any]]):
        for file_info in file_index.values():
            for chunk in file_info["chunks"]:
                key_id = chunk["key_id"]
                self._ipfs_client.pin.add(key_id, **self._ipfs_defaults)

    def _check_if_files_are_pinned(self, file_index: Dict[str, Dict[str, Any]]) -> bool:
        for file_info in file_index.values():
            for chunk in file_info["chunks"]:
                key_id = chunk["key_id"]
                if not self._is_pinned(key_id):
                    return False
        return True

    def _is_pinned(self, key_id: str) -> bool:
        try:
            self._ipfs_client.pin.ls(key_id, **self._ipfs_defaults)
        except ipfshttpclient.exceptions.ErrorResponse as er:
            if er.args[0] == 'not pinned':
                return False
            raise er
        return True
    
    def unpin(self,
              published_name: Optional[str] = None,
              index_from_net: bool = False,
              index_id_from_net: bool = False):
        index_key_id = self._resolve_index_key_id(
            published_name = published_name,
            index_id_from_net = index_id_from_net
        )
        try:
            self._ipfs_client.pin.rm(
                index_key_id,
                **self._ipfs_defaults
            )
        except ipfshttpclient.exceptions.ErrorResponse as er:
            if er.args[0] == "not pinned or pinned indirectly":
                print(f"Index can't be unpinned.")
            else:
                raise er
        file_index = self._open_index(
            published_name = published_name,
            index_from_net = index_from_net,
            index_id_from_net = index_id_from_net
        )
        self._unpin_files(file_index)

    def _unpin_files(self, file_index: Dict[str, Dict[str, Any]]):
        for file_info in file_index.values():
            for chunk in file_info["chunks"]:
                key_id = chunk["key_id"]
                try:
                    self._ipfs_client.pin.rm(
                        key_id,
                        **self._ipfs_defaults
                    )
                except ipfshttpclient.exceptions.ErrorResponse as er:
                    if er.args[0] == "not pinned or pinned indirectly":
                        print(f"File '{file_info['path']}' can't be unpinned.")
                    else:
                        raise er

    def _store_index_locally(self, file_index: Dict[str, Dict[str, Any]]):
        self._backup_and_remove_file(self._index_file)
        with open(self._index_file, "x") as f:
            json.dump(file_index, f)

    def _save_key_id(self, key_id: str, file_name: str):
        self._backup_and_remove_file(file_name)
        with open(file_name, "x") as f:
            json.dump(key_id, f)

    @staticmethod
    def _backup_and_remove_file(file_name: str):
        if not os.path.isfile(file_name):
            return
        backup_index_file = file_name + "-" + \
            datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        shutil.copyfile(file_name, backup_index_file)
        os.remove(file_name)

    def _store_index_on_network(self, file_index: Dict[str, Dict[str, Any]]) -> str:
        encoded = json.dumps(file_index).encode()
        encrypted = self._crypto.encrypt(encoded)
        key_id = self._ipfs_client.add_bytes(encrypted, **self._ipfs_defaults)
        # Pin index too.
        self._ipfs_client.pin.add(key_id, **self._ipfs_defaults)
        return key_id

    def restore(self,
                published_name: Optional[str] = None,
                destiny: str = "",
                index_from_net: bool = False,
                index_id_from_net: bool = False):
        file_index = self._open_index(
            published_name = published_name,
            index_from_net = index_from_net,
            index_id_from_net = index_id_from_net
        )
        for file_info in file_index.values():
            print(f"Restoring {file_info['path']}")
            chunks = file_info["chunks"]
            for chunk in chunks:
                data = self._ipfs_client.cat(chunk["key_id"], **self._ipfs_defaults)
                chunk["data"] = data
            file_chunks = FileChunks()
            file_chunks.merge(file_info,
                              self._password,
                              root_path=destiny)

    def _open_index(self,
                    published_name: Optional[str] = None,
                    index_from_net: bool = False,
                    index_id_from_net: bool = False) -> Dict[str, Dict[str, Any]]:
        file_index = dict()
        if not index_from_net:
            file_index = self._get_index_from_file()
        if not file_index:
            index_key_id = self._resolve_index_key_id(
                published_name,
                index_id_from_net
            )
            file_index = self._get_index_from_network(index_key_id)
        if not file_index:
            raise NoFileIndexException()
        return file_index
    
    def _resolve_index_key_id(self,
                              published_name: Optional[str] = None,
                              index_id_from_net: bool = False) -> str:
        index_key_id = ""
        if published_name:
            index_id_from_net = True
        if not index_id_from_net:
            index_key_id = self._get_index_key_id_from_file()
        if not index_key_id:
            index_key_id = self._get_index_key_id_from_network(published_name)
        if not index_key_id:
            raise NoKeyIDException()
        return index_key_id

    def _get_index_key_id_from_file(self) -> str:
        index_key_id = ""
        try:
            with open(self._index_key_id_file, "r") as f:
                index_key_id = json.load(f)
        except Exception as ex:
            print(f"Can't get key id from file: {ex}")
        return index_key_id

    def _get_index_key_id_from_network(self, published_name: Optional[str] = None) -> str:
        key_id = ""
        try:
            if not published_name:
                with open(self._published_name_file, "r") as f:
                    published_name = json.load(f)
            path = self._ipfs_client.name.resolve(
                published_name,
                nocache=True,
                **self._ipfs_defaults
            )
            key_id = path['Path'][6:]  # remove '/ipfs/'
        except Exception as ex:
            print(f"Can't get published name from network: {ex}")
        return key_id

    def _get_index_from_file(self) -> Dict[str, Dict[str, Any]]:
        file_index = dict()
        try:
            with open(self._index_file, "r") as f:
                file_index = json.load(f)
        except Exception as ex:
            print(f"Can't get index from file: {ex}")
        return file_index

    def _get_index_from_network(self, index_key_id: str) -> Dict[str, Dict[str, Any]]:
        file_index = dict()
        try:
            data_from_network = self._ipfs_client.cat(
                index_key_id,
                **self._ipfs_defaults
            )
            decrypted = self._crypto.decrypt(data_from_network)
            file_index = json.loads(decrypted)
        except Exception as ex:
            print(f"Can't get index from network: {ex}")
        return file_index

    def close(self) -> None:
        self._ipfs_client.disconect(**self._ipfs_defaults)

    def _ignore_file(self, file_name) -> bool:
        for pattern in self._ignore_file_regexs:
            if pattern.search(file_name):
                return True
        return False

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close


class FileChunks():
    def __init__(self,
                 chunk_size: int = 4 * 1024 * 1024):
        self._chunk_size = chunk_size
        self._chunked_file_info = {
            "chunks": [],
            "hash": "",
            "size": "",
            "absolute_path": "",
            "path": "",
            "chunk_size": chunk_size,
            "type": ""
        }
        pass

    @staticmethod
    def _hash_file(file_name) -> str:
        BUF_SIZE = 65536
        sha256 = hashlib.sha256()
        with open(file_name, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()

    def _hash_block(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _encrypt_block(password: str, data: bytes) -> bytes:
        cipher = AESCipher(password)
        return cipher.encrypt(data)

    @staticmethod
    def _decrypt_block(password: str, data: bytes) -> bytes:
        cipher = AESCipher(password)
        return cipher.decrypt(data)

    def create(self, file_name: str, password: str) -> Optional[ChunksFileInfo]:
        absolute_path = os.path.abspath(file_name)
        file_type = self._find_type(absolute_path)
        file_name = absolute_path[absolute_path.startswith(os.getcwd()) and len(os.getcwd()):]
        file_name = "." + file_name
        print(file_name)
        self._chunked_file_info["absolute_path"] = absolute_path
        self._chunked_file_info["path"] = file_name
        self._chunked_file_info["hash"] = self._hash_file(absolute_path)
        self._chunked_file_info["size"] = os.path.getsize(absolute_path)
        self._chunked_file_info["type"] = file_type
        if file_type == "directory":
            return self._chunked_file_info
        elif file_type == "link":
            return None
        chunks = list()
        with open(absolute_path, 'rb') as f:
            while True:
                data = f.read(self._chunk_size)
                if not data:
                    break
                encrypted = self._encrypt_block(password, data)
                data_hash = self._hash_block(encrypted)
                chunk = dict()
                chunk["key_id"] = ""
                chunk["data"] = encrypted
                chunk["hash"] = data_hash
                chunk["size"] = len(encrypted)
                chunks.append(chunk)
        self._chunked_file_info["chunks"] = chunks
        return self._chunked_file_info

    def merge(self,
              chunked_file_info: ChunksFileInfo,
              password: str,
              root_path: str = ""):
        chunks = chunked_file_info["chunks"]
        root_path = root_path + '/' if root_path else root_path
        file_path = os.path.normpath(
            root_path + \
            chunked_file_info["path"]
        )
        file_path = os.path.abspath(file_path)
        if chunked_file_info["type"] == "directory":
            os.makedirs(file_path)
            return
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(file_path, "xb") as f:
            for chunk in chunks:
                encrypted = chunk["data"]
                if len(encrypted) != chunk["size"]:
                    raise InvalidChunk(f"invalid chunk size")
                data_hash = self._hash_block(encrypted)
                if data_hash != chunk["hash"]:
                    raise InvalidChunk(f"invalid block of {file_path}, hash failed")
                decrypted = self._decrypt_block(password, encrypted)
                f.write(decrypted)
        file_hash = self._hash_file(file_path)
        if file_hash != chunked_file_info['hash']:
            raise CantRestoreFile(f"can't restore file {file_path}")
    
    @staticmethod
    def _find_type(name):
        if os.path.isfile(name) and not os.path.islink(name):
            return "file"
        elif os.path.islink(name):
            return "link"
        elif os.path.isdir(name):
            return "directory"
        else:
            raise UnknownType()


class AESCipher(object):

    def __init__(self, key: str): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: bytes) -> bytes:
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc: bytes) -> bytes:
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, data: bytes) -> bytes:
        length = self.bs - (len(data) % self.bs)
        data += bytes([length])*length
        return data

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        data = data[:-int(data[-1])]
        return data


class MaxFileSizeException(Exception):
    pass


class NoKeyIDException(Exception):
    pass


class NoFileIndexException(Exception):
    pass


class NotIsFileException(Exception):
    pass


class InvalidChunk(Exception):
    pass


class CantRestoreFile(Exception):
    pass


class UnknownType(Exception):
    pass


def ask_password(check: bool = False) -> str:
    if not check:
        return getpass.getpass()

    pprompt = lambda: (getpass.getpass(), getpass.getpass('Retype password: '))

    p1, p2 = pprompt()
    while p1 != p2:
        print('Passwords do not match. Try again')
        p1, p2 = pprompt()

    return p1


if __name__ == "__main__":
    # TODO: stat?
    # BUG: não faz backup de diretório vazio.

    parser = argparse.ArgumentParser(
        prog="bak2ipfs",
        description='Backup a directory to ipfs.',
        epilog='''
            bak2ipfs uses ipfs network to store encrypted
            files, good look with that!
        '''
    )

    parser.add_argument(
        '--index-file',
        help="File with the backup index.",
        type=str,
        default=".ipfs.index"
    )
    parser.add_argument(
        '--index-id-file',
        help="File with the backup index id (IPFS key value for the index).",
        type=str,
        default=".ipfs.index.key_id"
    )
    parser.add_argument(
        '--addrs',
        help="Address of the http api server.",
        type=str,
        default="/ip4/127.0.0.1/tcp/5001/http"
    )

    subparsers = parser.add_subparsers(dest='sub_command')

    parser_unpin = subparsers.add_parser('unpin')
    parser_unpin.add_argument(
        '--publish-name',
        help="IPFS key id for the backup index.",
        type=str
    )
    parser_unpin.add_argument(
        '--get-index',
        help="Get backup index from the IPFS.",
        type=bool,
        default=False
    )
    parser_unpin.add_argument(
        '--get-index-id',
        help="Get backup index id (key id that points to the backup index) from the IPFS.",
        type=bool,
        default=False
    )

    parser_backup = subparsers.add_parser('backup')
    parser_backup.add_argument(
        'source',
        default=".",
        help="origin directory to backup",
        type=str
    )
    parser_backup.add_argument(
        '--no-pin',
        help="Pin backup to this machine.",
        action='store_true'
    )

    parser_restore = subparsers.add_parser('restore')
    parser_restore.add_argument(
        'destiny',
        help="restore backup to destiny directory",
        type=str
    )
    parser_restore.add_argument(
        '--publish-name',
        help="IPFS key id for the backup index.",
        type=str,
        default=""
    )
    parser_restore.add_argument(
        '--get-index',
        help="Get backup index from the IPFS.",
        type=bool,
        default=False
    )
    parser_restore.add_argument(
        '--get-index-id',
        help="Get backup index id (key id that points to the backup index) from the IPFS.",
        type=bool,
        default=False
    )

    parsed_args = parser.parse_args()

    try:
        if not parsed_args.sub_command:
            parser.print_help()
            sys.exit(1)
        elif parsed_args.sub_command == 'backup':
            if not parsed_args.source:
                parser.print_help()
                sys.exit(1)
            password = ask_password(check=True)
            with Backup2ipfs(
                password,
                ipfs_addrs=parsed_args.addrs,
                root_dir=parsed_args.source,
                ignore=[r'\.git*', r'\.vscode*']
            ) as ipfs_backup:
                ipfs_backup.backup()
                if parsed_args.no_pin is True:
                    ipfs_backup.unpin()
        elif parsed_args.sub_command == 'restore':
            password = ask_password()
            with Backup2ipfs(
                password,
                ipfs_addrs=parsed_args.addrs,
                index_key_id_file=parsed_args.index_id_file,
                index_file=parsed_args.index_file
            ) as ipfs_backup:
                ipfs_backup.restore(
                    destiny=parsed_args.destiny,
                    published_name=parsed_args.publish_name,
                    index_id_from_net=parsed_args.get_index_id,
                    index_from_net=parsed_args.get_index
                )
        elif parsed_args.sub_command == 'unpin':
            password = ask_password()
            with Backup2ipfs(
                password,
                ipfs_addrs=parsed_args.addrs,
                index_key_id_file=parsed_args.index_id_file,
                index_file=parsed_args.index_file
            ) as ipfs_backup:
                ipfs_backup.unpin(
                    published_name=parsed_args.publish_name,
                    index_id_from_net=parsed_args.get_index_id,
                    index_from_net=parsed_args.get_index
                )
    except (NoFileIndexException, NoKeyIDException):
        sys.exit(2)
    except Exception as ex:
        print("Backup failed with error:", ex)
        sys.exit(3)
