import xml.etree.ElementTree as ET
from pathlib import Path

class ConfigReader:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigReader, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        try:
            config_path = Path(__file__).parent / "Web.config"
            
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found at {config_path}")
            
            tree = ET.parse(config_path)
            root = tree.getroot()
            
            # Database URLs
            self.MONGODB_URI = self._get_config_value(root, "MONGODB_URI")
            self.MONGODB_DATABASE = self._get_config_value(root, "MONGODB_DATABASE")
            
            # Security
            self.SECRET_KEY = self._get_config_value(root, "SECRET_KEY")
            self.ADMIN_SECRET_KEY = self._get_config_value(root, "ADMIN_SECRET_KEY", 
                                                         default=self._get_config_value(root, "SECRET_KEY"))
            self.ALGORITHM = self._get_config_value(root, "ALGORITHM")
            
            # Paths
            self.DATABASE_DIRECTORY = self._get_config_value(root, "DATABASE_DIRECTORY")
            self.LOGS_DIRECTORY = self._get_config_value(root, "LOGS_DIRECTORY")
            self.TEMPLATES_DIRECTORY = self._get_config_value(root, "TEMPLATES_DIRECTORY")
            
            # Log files
            self.USER_LOG_FILE = self._get_config_value(root, "USER_LOG_FILE")
            self.ADMIN_LOG_FILE = self._get_config_value(root, "ADMIN_LOG_FILE")
            self.QUEUE_LOG_FILE = self._get_config_value(root, "QUEUE_LOG_FILE")
            self.VACCINE_LOG_FILE = self._get_config_value(root, "VACCINE_LOG_FILE")
            
            # Database files
            self.MONGODB_URI = self._get_config_value(root, "MONGODB_URI")
            self.MONGODB_DATABASE = self._get_config_value(root, "MONGODB_DATABASE")
            
            # Server settings
            self.SERVER_MAINTENANCE_MODE = self._get_config_value(root, "SERVER_MAINTENANCE_MODE", "false").lower() == "true"
            self.SERVER_QUARANTINE_MODE = self._get_config_value(root, "SERVER_QUARANTINE_MODE", "false").lower() == "true"
            self.TOKEN_EXPIRE_MINUTES = int(self._get_config_value(root, "TOKEN_EXPIRE_MINUTES", "15"))
            self.RECRIPTION_PROCESS = self._get_config_value(root, "RECRIPTION_PROCESS", "false").lower() == "true"
            
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {str(e)}")
    
    def _get_config_value(self, root, key_name, default=None):
        for elem in root.findall(".//add"):
            if elem.get('key') == key_name:
                value = elem.get('value')
                if not value:
                    if default is not None:
                        return default
                    raise ValueError(f"Empty value for {key_name} in config")
                return value
        if default is not None:
            return default
        raise ValueError(f"{key_name} not found in config")

config = ConfigReader()