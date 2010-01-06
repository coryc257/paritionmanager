=begin
***************************************************************************
*   Copyright (C) 2008,2009,2010 by Volker Lanz <vl@fidra.de>             *
*   Copyright (C) 2007-2008 by Harald Sitter <harald@getamarok.com>       *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA            *
***************************************************************************
=end

require 'application.rb'
require 'tagger.rb'
require 'translationstatsbuilder.rb'
require 'fileutils'
require 'getoptlong'

class ReleaseBuilder

public
	def initialize(checkoutFrom, checkoutTag, app, workingDir, protocol, user, version)
		@checkoutFrom = checkoutFrom
		@checkoutTag = checkoutTag
		@app = app
		@workingDir = workingDir
		@protocol = protocol
		@user = user
		@version = version
		
		@outputDir = "#{@app.name}-#{@version}"
		
		FileUtils.rm_rf @outputDir
		FileUtils.rm_rf "#{@outputDir}.tar.bz2"
	end

	def run(createTarball, getTranslations, skipBelow, getDocs, createTag, applyFixes)
		checkoutSource
		translations = checkoutTranslations(skipBelow) if getTranslations
		docs = checkoutDocumentation if getDocs
		
		if createTag
			# TODO: fix the tagger so it no longer assumes the source is always trunk
#			repositoryDest = ReleaseBuilder.repositoryRoot(@protocol, @user) + ReleaseBuilder.repositoryPath('src', @app, 'tags', @version)
#			tagger = Tagger.new(repositoryDest, @app, @version)
#			tagger.tagSource
#			tagger.tagTranslations(translations)
#			tagger.tagDocumentation(docs)
		end

		@app.applyFixes(@workingDir, @outputDir) if applyFixes
		
		self.createTarball if createTarball
	end

	def checkoutSource
		Dir.chdir @workingDir
		
		repository = ReleaseBuilder.repositoryRoot(@protocol, @user) + ReleaseBuilder.repositoryPath('src', @app, @checkoutFrom, @checkoutTag)
		puts "Checking out source from #{repository} to output directory #{@outputDir}..."

		`svn co #{repository} #{@outputDir}`
	end

	def checkoutTranslations(skipBelow)
		puts "checking out translations, checkoutfrom: #{@checkoutFrom}"
		Dir.chdir "#{@workingDir}/#{@outputDir}"
	
		FileUtils.rm_rf 'l10n'
		FileUtils.rm_rf 'po'
		
		repository = ReleaseBuilder.repositoryRoot(@protocol, @user) + ReleaseBuilder.repositoryPath('i18n', @app, @checkoutFrom, @checkoutTag)

		puts "checking translations out from: #{repository}"

		translations = []

		if @checkoutFrom == 'trunk'
			puts "checkout from is apparently trunk"

			Dir.mkdir 'l10n'
			Dir.mkdir 'po'

			subdirs = `svn cat #{repository}/subdirs 2>/dev/null`.chomp!

			subdirs.each do |lang|
				lang.chomp!
				next if lang == 'x-test'

				FileUtils.rm_rf 'l10n'
				`svn co #{repository}/#{lang}/messages/#{@app.component}-#{@app.section} l10n >/dev/null 2>&1`
				next unless FileTest.exists? "l10n/#{@app.name}.po"

				if skipBelow > 0
					fuzzy, untranslated, per = TranslationStatsBuilder.fileStats("l10n/#{@app.name}.po")
					puts "Language #{lang} is #{per} % complete."
					next if per < skipBelow
				end
				
				puts "Adding translations for #{lang}..."
				
				dest = "po/#{lang}"
				Dir.mkdir dest
				
				FileUtils.mv("l10n/#{@app.name}.po", dest)
				FileUtils.mv('l10n/.svn', dest)

				File.open("#{dest}/CMakeLists.txt", File::CREAT | File::RDWR | File::TRUNC) do |f|
					f.print <<END_OF_TEXT
file(GLOB _po_files *.po)
GETTEXT_PROCESS_PO_FILES(#{lang} ALL INSTALL_DESTINATION ${LOCALE_INSTALL_DIR} ${_po_files})
END_OF_TEXT
				end

				`svn add #{dest}/CMakeLists.txt >/dev/null 2>&1`
				translations << lang
			end
		else
			puts "checkout from is not trunk, checking out from #{repository}"
			`svn co #{repository}`
			Dir.entries('po').sort.each do |lang|
				next if lang == 'CMakeLists.txt' or lang == '.' or lang == '..' or lang == '.svn'
				
				# TODO: this is just copied from above; also, the skipBelow test is missing here
				File.open("po/#{lang}/CMakeLists.txt", File::CREAT | File::RDWR | File::TRUNC) do |f|
					f.print <<END_OF_TEXT
file(GLOB _po_files *.po)
GETTEXT_PROCESS_PO_FILES(#{lang} ALL INSTALL_DESTINATION ${LOCALE_INSTALL_DIR} ${_po_files})
END_OF_TEXT
				end
				
				translations << lang
			end
		end

		if translations.length > 0
			File.open('po/CMakeLists.txt', File::CREAT | File::RDWR | File::TRUNC) do |f|
				f.print <<END_OF_TEXT

find_package(Gettext REQUIRED)

if (NOT GETTEXT_MSGMERGE_EXECUTABLE)
	message(FATAL_ERROR "Please install the msgmerge program from the gettext package.")
endif (NOT GETTEXT_MSGMERGE_EXECUTABLE)

if (NOT GETTEXT_MSGFMT_EXECUTABLE)
	message(FATAL_ERROR "Please install the msgfmt program from the gettext package.")
endif (NOT GETTEXT_MSGFMT_EXECUTABLE)

END_OF_TEXT

				translations.each { |lang| f.print "add_subdirectory(#{lang})\n" }
			end
	
			File.open('CMakeLists.txt', File::APPEND | File::RDWR) do |f|
				f.print <<END_OF_TEXT
include(MacroOptionalAddSubdirectory)
macro_optional_add_subdirectory(po)
END_OF_TEXT
			end

			# TODO: turn on again and check
			TranslationStatsBuilder.new(@app.name, @version, @workingDir, @outputDir).run
		else
			FileUtils.rm_rf 'po'
		end

		FileUtils.rm_rf 'l10n'

		return translations
	end

	def checkoutDocumentation
		Dir.chdir "#{@workingDir}/#{@outputDir}"
	
		docs = [ "en_US" ]
		repository = ReleaseBuilder.repositoryRoot(@protocol, @user) + ReleaseBuilder.repositoryPath('doc', @app, @checkoutFrom, @checkoutTag)

		if @checkoutFrom == 'trunk'
			# the english docs are the super-extra-exception: they reside near, but not with, the code
			usDocsRepo = ReleaseBuilder.repositoryRoot(@protocol, @user) + "trunk"

			`svn co #{usDocsRepo}/#{@app.component}/#{@app.section}/doc/#{@app.name} doc/en_US >/dev/null 2>&1`

			if not File.exists? 'doc/en_US/index.docbook'
				FileUtils.rm_rf 'doc'
				return nil
			end
			
			File.open("doc/en_US/CMakeLists.txt", File::CREAT | File::RDWR | File::TRUNC) do |f|
				f << "kde4_create_handbook(index.docbook INSTALL_DESTINATION \${HTML_INSTALL_DIR}/en_US/ SUBDIR #{@app.name})\n"
			end

			# now, the rest of the docs are localized, so reside somewhere else
			subdirs = `svn cat #{repository}/subdirs 2>/dev/null`.chomp!
			
			subdirs.each do |lang|
				lang.chomp!

				FileUtils.rm_rf 'l10n'
				`svn co #{repository}/#{lang}/docs/#{@app.component}-#{@app.section}/#{@app.name} l10n >/dev/null 2>&1`
				next unless FileTest.exists? 'l10n/index.docbook'

				puts "Adding documentation for #{lang}..."

				dest = "doc/#{lang}"
				FileUtils.mv('l10n', dest)

				File.open("doc/#{lang}/CMakeLists.txt", File::CREAT | File::RDWR | File::TRUNC) do |f|
					f << "kde4_create_handbook(index.docbook INSTALL_DESTINATION \${HTML_INSTALL_DIR}/#{lang}/ SUBDIR #{@app.name})\n"
				end

				`svn add doc/#{lang}/CMakeLists.txt >/dev/null 2>&1`
				docs << lang
			end
		else
			`svn co #{repository}`
			return nil if not FileTest.exists? 'doc'
			Dir.entries('doc').sort.each do |lang|
				next if lang == 'CMakeLists.txt' or lang == '.' or lang == '..' or lang == '.svn'
				docs << lang
			end
		end
		
		File.open('doc/CMakeLists.txt', File::CREAT | File::RDWR | File::TRUNC) do |f|
			docs.each { |lang| f << "add_subdirectory(#{lang})\n" }
		end

		File.open('CMakeLists.txt', File::APPEND | File::RDWR) do |f|
			f << "include(MacroOptionalAddSubdirectory)\n" unless File.exists? 'po'
			f << "macro_optional_add_subdirectory(doc)\n"
		end

		FileUtils.rm_rf 'l10n'

		return docs
	end

	def createTarball
		Dir.chdir @workingDir
	
		tarBzFileName = "#{@outputDir}.tar.bz2"
		tarGzFileName = "#{@outputDir}.tar.gz"
	
		`find #{@outputDir} -name .svn | xargs rm -rf`
		`tar cfj #{tarBzFileName} #{@outputDir}`
		`tar cfz #{tarGzFileName} #{@outputDir}`
		`rm -rf #{@outputDir}`
		
		puts "bz2 MD5:  " + `md5sum #{tarBzFileName}`.split[0]
		puts "bz2 SHA1: " + `sha1sum #{tarBzFileName}`.split[0]

		puts "gz MD5:  " + `md5sum #{tarGzFileName}`.split[0]
		puts "gz SHA1: " + `sha1sum #{tarGzFileName}`.split[0]
	end

	def self.repositoryRoot(protocol, user)
		if protocol == 'anonsvn'
			protocol = 'svn'
			user = 'anon'
		else
			user += "@"
		end
	
		return "#{protocol}://#{user}svn.kde.org/home/kde/"
	end
	
	def self.repositoryPath(type, app, checkoutFrom, tag)
		
		if type == 'src'

			rval = case checkoutFrom
				when 'trunk' then "trunk/#{app.component}/#{app.section}/#{app.name}"
				when 'branches' then "branches/#{app.name}/#{tag}/#{app.name}"
				when 'tags' then "tags/#{app.name}/#{tag}/#{app.name}"
				else "### invalid checkout source: #{checkoutFrom} ###"
			end

		elsif type == 'i18n'

			rval = case checkoutFrom
				when 'trunk' then "trunk/l10n-kde4/" # followed by $lang/messages/#{app.component}-#{app.section}/#{app.name}.po, but the code has to deal with that
				when 'branches' then "branches/#{app.name}/#{tag}/po"
				when 'tags' then "tags/#{app.name}/#{tag}/po"
				else "### invalid checkout source: #{checkoutFrom} ###"
			end
			
		elsif type == 'doc'

			rval = case checkoutFrom
				when 'trunk' then "trunk/l10n-kde4/" # see above
				when 'branches' then "branches/#{app.name}/#{tag}/doc"
				when 'tags' then "tags/#{app.name}/#{tag}/doc"
				else "### invalid checkout source: #{checkoutFrom} ###"
			end
			
		end

		return rval
	end
end

