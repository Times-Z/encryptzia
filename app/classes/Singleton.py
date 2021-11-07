class Singleton:
    def __init__(self, cls):
        self._cls = cls

    def Instance(self, *args):
        try:
            return self._instance
        except AttributeError:
            if not len(args):
                self._instance = self._cls()
            else:
                self._instance = self._cls(args[0])
            return self._instance

    def __call__(self):
        raise TypeError('Singletons must be accessed through `Instance()`.')

    def __instancecheck__(self, inst):
        return isinstance(inst, self._cls)