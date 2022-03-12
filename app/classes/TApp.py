# -*- coding: utf-8 -*-
from textual.app import App
from textual.widgets import Placeholder, Button


class Tapp(App):

    async def on_mount(self) -> None:
        await self.view.dock(Button(label="Toto"), Placeholder(), Placeholder(), edge="top")
        await self.bind("A", "default_act", "Execute action")

    def default_act(self):
        print('toto')