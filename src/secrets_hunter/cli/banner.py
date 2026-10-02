import random


LOGO_ASCII_FILLED = r"""

    ███████╗██╗   ██╗██╗      ██████╗███╗   ██╗
    ██╔════╝██║   ██║██║     ██╔════╝████╗  ██║
    █████╗  ██║   ██║██║     ██║     ██╔██╗ ██║
    ██╔══╝  ╚██╗ ██╔╝██║     ██║     ██║╚██╗██║
    ██║      ╚████╔╝ ███████╗╚██████╗██║ ╚████║
    ╚═╝       ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═══╝
"""

LOGO_ASCII_HOLLOW = r"""
   ________ ___      ___ ___       ________  ________      
  |\  _____\\  \    /  /|\  \     |\   ____\|\   ___  \    
  \ \  \__/\ \  \  /  / | \  \    \ \  \___|\ \  \\ \  \   
   \ \   __\\ \  \/  / / \ \  \    \ \  \    \ \  \\ \  \  
    \ \  \_| \ \    / /   \ \  \____\ \  \____\ \  \\ \  \ 
     \ \__\   \ \__/ /     \ \_______\ \_______\ \__\\ \__\
      \|__|    \|__|/       \|_______|\|_______|\|__| \|__|
"""


def display_logo_with_version(logo: str, version: str) -> None:
    version_text = f"Secrets Hunter v{version}"
    logo_lines = logo.strip("\n").split("\n")
    logo_width = max(len(line) for line in logo_lines)
    padding = logo_width - len(version_text)
    print(f"{logo}\n{' ' * padding}{version_text}\n")


def display_random_logo(version: str) -> None:
    logo = LOGO_ASCII_FILLED if random.random() < 0.05 else LOGO_ASCII_HOLLOW
    display_logo_with_version(logo, version)
