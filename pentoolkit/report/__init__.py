class ReportEngine:
    def __init__(self, config=None):
        if config:
            self.template_path = config.reporting.template
            self.static_dir = config.reporting.static_dir
        else:
            # fallback if CLI doesn't pass config
            from pentoolkit.config import ConfigLoader
            cfg = ConfigLoader().load()
            self.template_path = cfg.reporting.template
            self.static_dir = cfg.reporting.static_dir

        self.results = {}
