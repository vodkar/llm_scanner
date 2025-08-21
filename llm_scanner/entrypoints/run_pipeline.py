from pathlib import Path

from pipeline import GeneralPipeline


def main():
    pipeline = GeneralPipeline(src=Path("sample path"))
    pipeline.run()


if __name__ == "__main__":
    main()
