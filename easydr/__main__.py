"""Point d'entrée unique : EasyDR.exe [--daemon | --scan-worker | --update | --ui]"""
import sys


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--ui"
    if mode == "--daemon":
        from . import daemon; daemon.main()
    elif mode == "--scan-worker":
        from . import worker; worker.main()
    elif mode == "--update":
        from . import signatures; signatures.main()
    elif mode == "--version":
        from . import __version__; print(__version__)
    else:
        from . import ui; ui.main()


if __name__ == "__main__":
    main()
