# flask_API_simple_exemple
Some simple flask exemple using API

vscode launch.json for debuggin

{
    "configurations": [
        {
            "name": "Python: Remote Attach",
            "type": "python",
            "request": "attach",
            "port": 10001,
            "host": "0.0.0.0",
            "pathMappings": [
            {
                "localRoot": "${workspaceFolder}/web",
                "remoteRoot":  "/web"
            }
            ]
        }
    ]
}