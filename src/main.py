import click


@click.group()
def cli():
    """TODO: Project Name

    TODO: Command Description
    """


@cli.command()
def encrypt():
    """
    TODO: document
    """
    # Actual algorithms should not go here
    # They should be defined in separate files and called from here
    print("TODO: implement encryption")
    pass


@cli.command()
def decrypt():
    """
    TODO: document
    """
    print("TODO: implement decryption")
    pass


if __name__ == "__main__":
    cli()
