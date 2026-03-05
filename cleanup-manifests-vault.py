#!/usr/bin/env python3

import os
import sys
import yaml
import glob
from pathlib import Path

class VaultMigrator:
    def __init__(self, manifest_dir="manifests"):
        self.manifest_dir = manifest_dir
        self.services = {
            "grafana": {
                "secret_path": "secret/data/grafana/admin",
                "password_var": "GF_SECURITY_ADMIN_PASSWORD"
            },
            "prometheus": {
                "secret_path": "secret/data/prometheus/config",
                "password_var": "PROMETHEUS_PASSWORD"
            },
            "code-server": {
                "secret_path": "secret/data/code-server",
                "password_var": "PASSWORD"
            },
            "vaultwarden": {
                "secret_path": "secret/data/vaultwarden/config",
                "password_var": "ADMIN_TOKEN"
            },
            "heimdall": {
                "secret_path": "secret/data/heimdall",
                "password_var": "ADMIN_PASSWORD"
            }
        }
        self.updated = 0
        self.skipped = 0
    
    def get_service_name(self, filepath):
        """Extract service name from file path"""
        parts = Path(filepath).parts
        if len(parts) >= 2:
            return parts[1]
        return None
    
    def has_vault_annotations(self, content):
        """Check if already has Vault annotations"""
        return "vault.hashicorp.com/agent-inject" in content
    
    def add_vault_annotations(self, data, service, secret_path, password_var):
        """Add Vault annotations to deployment"""
        if not data or 'spec' not in data or 'template' not in data['spec']:
            return False
        
        template = data['spec']['template']
        
        # Add annotations
        if 'metadata' not in template:
            template['metadata'] = {}
        
        if 'annotations' not in template['metadata']:
            template['metadata']['annotations'] = {}
        
        annotations = template['metadata']['annotations']
        annotations['vault.hashicorp.com/agent-inject'] = 'true'
        annotations['vault.hashicorp.com/role'] = service
        annotations[f'vault.hashicorp.com/agent-inject-secret-{service}'] = secret_path
        
        # Create template string
        template_str = (
            f'{{{{- with secret "{secret_path}" -}}}}\\n'
            f'export {password_var}="{{{{ .Data.data.password }}}}"\\n'
            f'{{{{- end }}}}'
        )
        
        annotations[f'vault.hashicorp.com/agent-inject-template-{service}'] = template_str
        
        # Remove hardcoded passwords from env
        spec = data['spec']['template']['spec']
        if 'containers' in spec:
            for container in spec['containers']:
                if 'env' in container:
                    # Filter out password-related env vars
                    new_env = []
                    for env in container['env']:
                        env_name = env.get('name', '')
                        if not any(keyword in env_name for keyword in ['PASSWORD', 'PASS', 'SECRET', 'TOKEN']):
                            new_env.append(env)
                    container['env'] = new_env if new_env else None
        
        # Add service account name
        if 'serviceAccountName' not in spec:
            spec['serviceAccountName'] = service
        
        return True
    
    def process_file(self, filepath):
        """Process a single manifest file with MULTIPLE YAML documents"""
        service = self.get_service_name(filepath)
        
        if service not in self.services:
            return
        
        print(f"Processing: {filepath}")
        
        # Read file
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if already has Vault annotations
        if self.has_vault_annotations(content):
            print(f"  ⚠ Already has Vault annotations, skipping")
            self.skipped += 1
            return
        
        # Parse MULTIPLE YAML documents
        try:
            documents = list(yaml.safe_load_all(content))
        except Exception as e:
            print(f"  ✗ Failed to parse YAML: {e}")
            return
        
        if not documents:
            return
        
        config = self.services[service]
        updated = False
        
        # Process each document in the file
        for i, data in enumerate(documents):
            if not data or 'kind' not in data:
                continue
            
            # Only process Deployments and StatefulSets
            if data['kind'] not in ['Deployment', 'StatefulSet']:
                continue
            
            # Update manifest
            if self.add_vault_annotations(data, service, config['secret_path'], config['password_var']):
                updated = True
                print(f"  ✓ Updated {data['kind']} - Vault annotations added")
        
        # Write back ALL documents
        if updated:
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump_all(documents, f, default_flow_style=False, sort_keys=False)
            self.updated += 1
    
    def run(self):
        """Process all manifests"""
        print("=== Manifest Cleanup for Vault ===\\n")
        
        # Find all YAML files
        yaml_files = glob.glob(os.path.join(self.manifest_dir, "**", "*.yaml"), recursive=True)
        
        if not yaml_files:
            print(f"No YAML files found in {self.manifest_dir}")
            return
        
        for filepath in yaml_files:
            self.process_file(filepath)
        
        print(f"\\n=== Summary ===")
        print(f"Updated: {self.updated}")
        print(f"Skipped: {self.skipped}")
        
        print(f"\\nNext steps:")
        print("1. Review changes in VS Code")
        print("2. Commit: git add manifests/ && git commit -m 'Security: Migrate to Vault'")
        print("3. Push: git push origin main")
        print("\\n✓ Cleanup complete!")

if __name__ == '__main__':
    migrator = VaultMigrator("manifests")
    migrator.run()