# Use uma imagem base como ponto de partida
FROM python:3.8

# Defina o diretório de trabalho dentro do contêiner
WORKDIR /AMExplorer

# Copie os arquivos específicos para o diretório de trabalho do contêiner
COPY adbuilder_dataset.py utils.py tool_test.zip run_test_tool.sh /AMExplorer/

# Converter o script para formato Unix (remover os caracteres \r)
RUN sed -i 's/\r//' run_test_tool.sh

# Dar permissões de execução ao script
RUN chmod +x run_test_tool.sh

# Instale as dependências
RUN pip install pandas termcolor

# Exponha a porta (caso seu aplicativo precise)
# EXPOSE 8080

# Comando para executar o seu script
CMD ["bash", "run_test_tool.sh"]

