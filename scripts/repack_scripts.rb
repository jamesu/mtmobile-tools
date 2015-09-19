#!/usr/bin/ruby

if ARGV[0] == 'pack'
	Dir.glob("script/**/*.606843546").each do |d|
		puts "Repacking #{d}..."
		system("gmdTool c #{d}.txt #{d};")
	end
elsif ARGV[0] == 'unpack'
	Dir.glob("script/**/*.606843546").each do |d|
		puts "Unpacking #{d}..."
		system("gmdTool d #{d} #{d}.txt;")
	end
end
