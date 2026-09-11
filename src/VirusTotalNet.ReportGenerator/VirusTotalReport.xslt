    <!--Start XSL-->
    <xsl:stylesheet id="stylesheet"
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:ps="http://schemas.microsoft.com/powershell/2004/04"
	xmlns:scanvirustotalprotocol="http://www.example.org/ScanVirusTotalProtocol">
    <xsl:template match="xsl:stylesheet" />
  
    <xsl:template match="/doc">
    <html>
    <head>
        <style>      
			table {
			width: 100%;
			font-family: Tahoma;
			border-collapse: collapse;
			font-size: 12px;
			}
			table, th, td {
			border: 1px solid black;
			text-align:left;
			}
			header{
			text-align:left;
			font-family: Tahoma;
			}
			footer {
			text-align:left;
			font-family: Tahoma;
			font-size: 12px;
			}
			.noBorder {
			border:none !important;
			}
			td {
				border:none !important;		
			}
			tr:nth-child(2n+1) {
				 background-color: #F5F5F5;
			}
			p.scanFile {
				font-size: 12px; 
				font-weight: bold; 
				font-family: Tahoma;
			}
			span {
				padding-left:3px;
			}
        </style>
        <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
    </head>
    <body>
		<header>
			<h1>VirusTotal Report</h1>
			<xsl:variable name="startDate" select="substring-before(ScanVirusTotalProtocol/header/startDateTime,'T')"/>
			<xsl:variable name="startTime" select="substring-after(ScanVirusTotalProtocol/header/startDateTime,'T')"/>
			<p><xsl:value-of select= '$startDate'/> <span> </span> <xsl:value-of select="substring-before($startTime,'.')"/> <span>(Duration <xsl:value-of select="ScanVirusTotalProtocol/header/executionTime"/>), </span></p>
			<p>All scanned files: <xsl:value-of select="ScanVirusTotalProtocol/header/fileScannedList"/></p>
		    <h3>
                <span style="color: #000000; cursor: pointer;" onclick="ShowTotal()" onmouseout="this.style.textDecoration='none';" onmouseover="this.style.textDecoration='underline';">
                    <xsl:value-of select="ScanVirusTotalProtocol/header/summaryScanCase" />
                </span>
                <span>, </span>
                <span style = "color: #6AC259; cursor: pointer;" onclick="ShowUndetecteds()" onmouseout="this.style.textDecoration='none';" onmouseover="this.style.textDecoration='underline';">
                    <xsl:value-of select="ScanVirusTotalProtocol/header/scanCaseUndetected" />
                </span>
                <span>, </span>
                <span style = "color: #eab765; cursor: pointer;" onclick="ShowDetecteds()" onmouseout="this.style.textDecoration='none';" onmouseover="this.style.textDecoration='underline';">
                    <xsl:value-of select="ScanVirusTotalProtocol/header/scanCaseDetected" />
                </span>
            </h3>
        </header>
		
		<xsl:variable name="scanfile" select="ScanVirusTotalProtocol/scanFile/ScanFile" />
        <xsl:variable name="countFileScan" select="count($scanfile)" />
		<xsl:choose>
			<xsl:when test='($countFileScan!= "0")'>
				<xsl:for-each select="ScanVirusTotalProtocol/scanFile/ScanFile"> 
					<div class="scanFile">
                    <p class="scanFile">File Scan: <span>
						<a target="_blank">
						<xsl:attribute name="href">
							<xsl:value-of select="permalink" />
						</xsl:attribute>
						<xsl:value-of select="pathFile"/>
						</a></span>
					</p>
					<xsl:variable name="teststep" select="scanSteps/ScanStepsScanStep" /> 
					<xsl:variable name="countTestStep" select="count($teststep)" /> 
					<xsl:choose> 
					<xsl:when test='($countTestStep != "0")'> 
                    <table class="noBorder" cellpadding="3">
					<tr style="background-color:#E0E0E0; color:#000000">  
						<th width="20px"></th>
						<th>Tool Engine</th>
						<th>Version</th>
						<th>Date updated</th>
						<th>Result Description</th>
					</tr>
					<xsl:for-each select="scanSteps/ScanStepsScanStep">
					<xsl:variable name="stepResult" select="result"/>					
					<tr style="text-align:center;">
			<xsl:choose>
			<xsl:when test='($stepResult = "Detected")'>
				<td class="detected"><svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="20px" height="20px" viewBox="0 0 32 32" enable-background="new 0 0 32 32" xml:space="preserve">
    <path d="M30.5748,26.2199L17.9813,3.2429c-0.9058,-1.6523,-3.1406,-1.6541,-4.0464,-0.0018L1.3414,26.2208C0.4257,27.8915,1.553,30,3.3646,30h25.187C30.3633,30,31.4906,27.8906,30.5748,26.2199zM18,25.6c0,0.22,-0.18,0.4,-0.4,0.4h-3.2c-0.22,0,-0.4,-0.18,-0.4,-0.4v-2.2c0,-0.22,0.18,-0.4,0.4,-0.4h3.2c0.22,0,0.4,0.18,0.4,0.4V25.6zM18,20.6c0,0.22,-0.18,0.4,-0.4,0.4h-3.2c-0.22,0,-0.4,-0.18,-0.4,-0.4V10.4c0,-0.22,0.18,-0.4,0.4,-0.4h3.2c0.22,0,0.4,0.18,0.4,0.4V20.6z" fill="#EAB765"/>
    <path d="M17.6,21h-3.2c-0.22,0,-0.4,-0.18,-0.4,-0.4V10.4c0,-0.22,0.18,-0.4,0.4,-0.4h3.2c0.22,0,0.4,0.18,0.4,0.4v10.2C18,20.82,17.82,21,17.6,21zM18,25.6v-2.2c0,-0.22,-0.18,-0.4,-0.4,-0.4h-3.2c-0.22,0,-0.4,0.18,-0.4,0.4v2.2c0,0.22,0.18,0.4,0.4,0.4h3.2C17.82,26,18,25.82,18,25.6z" fill="#58595B"/>
</svg></td>
			</xsl:when>
			<xsl:otherwise>
				<td class="undetected"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" id="Layer_1" x="0px" y="0px" width="19px" height="19px" viewBox="0 0 426.667 426.667" style="enable-background:new 0 0 426.667 426.667;" xml:space="preserve">
<path style="fill:#6AC259;" d="M213.333,0C95.518,0,0,95.514,0,213.333s95.518,213.333,213.333,213.333  c117.828,0,213.333-95.514,213.333-213.333S331.157,0,213.333,0z M174.199,322.918l-93.935-93.931l31.309-31.309l62.626,62.622  l140.894-140.898l31.309,31.309L174.199,322.918z"></path></svg></td>
			</xsl:otherwise>
			</xsl:choose>
						<td><xsl:value-of select="toolAntivirus"/></td>
						<td><xsl:value-of select="vesion" /></td>
						<td><xsl:value-of select="updateDate"/></td>
						<td><xsl:value-of select="resultDescription"/></td>
					</tr>
					</xsl:for-each>	   
					</table>
                    </xsl:when>
			        </xsl:choose>
                </div>
				</xsl:for-each>
			</xsl:when>
		</xsl:choose>
		
		<footer>	  
		  <p align="right">Made with <a href="https://www.emotive.de/" target="_blank">emotive</a></p>
		</footer>

        <script>
			function ShowTotal() {
				$('div.scanFile').each(function() {
					$(this).show();
					$(this).children().show();	
					$(this).find('tbody').children().show();
				});	
			}
			function ShowDetecteds() {
				$('.noBorder tr:has(td.detected)').show();
				$('.noBorder tr:has(td.undetected)').hide();
                FilterTable();
			}
			function ShowUndetecteds() {
				$('.noBorder tr:has(td.detected)').hide();
				$('.noBorder tr:has(td.undetected)').show();
                FilterTable()
			}
            function FilterTable() {	
				UnFilterTable();						
				$('table').each(function() {	
					var countTotalRow = $(this).find('tbody').children().length - 1;
					var countHiddnenRow = $(this).find('tbody').children('tr').filter(function() {
						  return $(this).css('display') === 'none';
					}).length;
					if(countHiddnenRow==countTotalRow) {
						$(this).parent().children().hide();
						$(this).parent().hide();
					}								
				});
				$('div.scanFile').each(function() {
					if($(this).children().length==1) {
						$(this).hide();
					}				
				});							
			}		
			function UnFilterTable() {
				$('div.scanFile').each(function() {
					$(this).show();
					$(this).children().show();	
				});	
			}
		</script>
    </body>
    </html>
    </xsl:template>
    </xsl:stylesheet>
	
