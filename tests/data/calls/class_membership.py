class Service:
    def helper(self, value):
        return value

    def vuln(self, raw):
        cleaned = raw
        return self.helper(cleaned)

    def s1(self):
        return 1

    def s2(self):
        return 2
