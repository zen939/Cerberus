# === build ===
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# 先還原（利用層快取）
COPY Cerberus.Shared/Cerberus.Shared.csproj Cerberus.Shared/
COPY Cerberus.Server/Cerberus.Server.csproj Cerberus.Server/
RUN dotnet restore Cerberus.Server/Cerberus.Server.csproj

# 再複製原始碼編譯
COPY Cerberus.Shared/ Cerberus.Shared/
COPY Cerberus.Server/ Cerberus.Server/
RUN dotnet publish Cerberus.Server/Cerberus.Server.csproj -c Release -o /app /p:UseAppHost=false

# === runtime ===
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# 健康檢查端點為 GET /health（由外部或 compose 監控）
ENTRYPOINT ["dotnet", "Cerberus.Server.dll"]
