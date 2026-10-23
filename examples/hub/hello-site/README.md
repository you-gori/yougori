# Hello site

A one-page website in a container. Run it, answer two questions, and it is online.

```text
yougori run hub/yougori/hello-site
```

It asks:

- what the page should say,
- where it should be reachable: a quick HTTPS link, one of your saved domains, or only this computer.

What it creates:

- one container (`python:3.12-slim`, 1 CPU, 1 GB memory, 6 GB disk) serving the page on port 8080,
- HTTPie inside that container, so you can check the site from its own shell.

To change the page, edit `site/index.html` in the instance folder that `yougori template status hello-site` shows, then run the template again.

This folder is also the reference example for writing your own template: see `yougori-template.yaml` next to the normal `yougori.yaml` project.
