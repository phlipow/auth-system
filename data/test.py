class ReturnError(Exception):
    def __init__(self, level):
        self.level = level
        super().__init__(level)

