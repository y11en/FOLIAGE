ENTRY( _BEG )

SECTIONS
{
	.text ALIGN(1) : SUBALIGN(1)
	{
		*(.text._BEG)
		*(.text.*)
	}
}
