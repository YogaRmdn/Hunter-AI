from core.llm_router import LLMRouter


class LLMClient:
    def __init__(self, provider: str = "opencode", api_key: str = None, model: str = ""):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.router = LLMRouter(preferred=provider, api_key=api_key, model=model)

    @property
    def history(self):
        return self.router.history

    def is_available(self) -> bool:
        for s in self.router.get_status():
            if s["available"]:
                return True
        return False

    def add_message(self, role: str, content: str):
        self.router.add_message(role, content)

    def query(self, prompt: str) -> str:
        return self.router.query(prompt)

    def decide(self, user_input: str, context: dict) -> dict:
        return self.router.decide(user_input, context)

    @property
    def active_provider(self) -> str:
        return self.router.active_provider
