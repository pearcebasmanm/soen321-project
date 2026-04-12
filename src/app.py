"""
Real-time secure chat entry point.
Starts a background thread to receive incoming messages.
Run two instances on two different machines to establish a live channel.
"""
import click
from threading import Thread

from websocket import listener_thread, message_send


@click.command()
@click.option("--port", default=8765, type=click.INT)
@click.option("--dest", default="localhost", type=click.STRING)
@click.option("--dest_port", default=8765, type=click.INT)
def app(port, dest, dest_port):
    click.echo(f"Sending to {dest} on port {dest_port} and listening on port {port}")
    click.echo("Type messages and press ENTER to send")
    click.echo("Incoming messages will be displayed as they are received")
    Thread(target=listener_thread, args=(port,), daemon=True).start()

    while True:
        message = input()
        message_send(dest, message, dest_port)


if __name__ == "__main__":
    app()
