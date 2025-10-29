import yaml

class PromptManager:
    """Handles formatting of the prompts"""
    def __init__(self, promptyaml, **default_params):
        
        with open(promptyaml, "r") as c:
            self.templates = yaml.safe_load(c)
        self.default_params = default_params

    def get(self, key, **kwargs):
        # TODO check if templating done properly
        tmpl = self.templates.get(key, "")
        
        all_params = self.default_params.copy()
        all_params.update(kwargs)

        prompt = tmpl.format(prompter=self, **all_params)
        return prompt