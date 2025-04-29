import os
import shutil
import logging
from xml.etree import ElementTree as ET
from config_reader import config

def check_recovery_needed():
    """Check if database recovery is needed after interrupted re-encryption"""
    try:
        config_file = "Web.config"
        if not os.path.exists(config_file):
            return False
            
        tree = ET.parse(config_file)
        root = tree.getroot()
        
        process_elements = root.findall(".//add[@key='RECRIPTION_PROCESS']")
        if not process_elements:
            return False
            
        if process_elements[0].get('value', '').lower() == 'true':
            logging.info("Recovery needed - RECRIPTION_PROCESS flag is True")
            
            # Restore databases from backup
            backup_dir = os.path.join(config.DATABASE_DIRECTORY, "backups")
            if not os.path.exists(backup_dir):
                logging.error("Backup directory not found")
                return False
                
            # Find all backup files
            backups = {}
            for file in os.listdir(backup_dir):
                if file.endswith(".bak"):
                    base_name = file.split('_')[0]
                    timestamp = file.split('_')[1] + '_' + file.split('_')[2].split('.')[0]
                    if base_name not in backups or timestamp > backups[base_name]['timestamp']:
                        backups[base_name] = {
                            'path': os.path.join(backup_dir, file),
                            'timestamp': timestamp
                        }
            
            # Restore each database file
            restored = False
            for base_name, backup_info in backups.items():
                original_path = os.path.join(config.DATABASE_DIRECTORY, base_name)
                if os.path.exists(backup_info['path']):
                    shutil.copy2(backup_info['path'], original_path)
                    restored = True
                    logging.info(f"Restored database: {base_name}")
            
            # Reset the flag
            process_elements[0].set('value', 'false')
            tree.write(config_file, encoding='utf-8', xml_declaration=True)
            logging.info("Reset RECRIPTION_PROCESS flag to False")
            
            return restored
        return False
    except Exception as e:
        logging.error(f"Failed to check for recovery: {str(e)}")
        return False