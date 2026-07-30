# VULN (Security Misconfiguration): single-stage build for benchmark
# simplicity; runs as root; base tag not pinned to digest.
FROM mcr.microsoft.com/dotnet/sdk:7.0

WORKDIR /app
COPY . .
RUN dotnet restore InventoryVuln.csproj
RUN dotnet publish InventoryVuln.csproj -c Release -o out

ENV ASPNETCORE_URLS=http://+:8083
EXPOSE 8083

CMD ["dotnet", "out/InventoryVuln.dll"]
