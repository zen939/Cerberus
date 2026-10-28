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

# 註：容器非 root 執行需搭配 volume 權限處理（Docker Desktop named volume 不繼承映像擁有權），
# 正解為 entrypoint 以 root chown /data 後用 gosu/su-exec 降權；此處暫以 root 執行以確保 SQLite 可寫。
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# 健康檢查端點為 GET /health（由外部或 compose 監控）
ENTRYPOINT ["dotnet", "Cerberus.Server.dll"]
