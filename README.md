# Secure Pipeline Lab

## High-Level Diagram

![Untitled](images/HLD.png)

## Low-level Diagram

{{ DIAGRAM HERE }}

## Development

Code gets pushed to Gitlab

## Code Repository

If prod branch, pipeline gets triggered

There are two gitlab runners to keep CI/CD and Production servers isolated. 

## Build

Build happens twice (it is actually nonsense for now)

- First time in CI/CD server for running unit test in docker container
- Second time in Production server to deploy

## Staging

There is no staging for this lab

## Production

Once unittests passed in CI/CD server, gitlab runner in production server pulls the code and deploys it using docker-compose.
After deployment, a container runs zap scanner from CI/CD server, using production server as a target

## Monitoring

We can integrate Elastic Stack later on 
